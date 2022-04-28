package artifact

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/reportk8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
)

// K8sRun runs scan on kubernetes cluster
func K8sRun(ctx *cli.Context) error {
	opt, err := initOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	if err = log.InitLogger(opt.Debug, true); err != nil {
		return err
	}

	cacheClient, err := initCache(opt)
	if err != nil {
		if errors.Is(err, errSkipScan) {
			return nil
		}
		return xerrors.Errorf("cache error: %w", err)
	}
	defer cacheClient.Close()

	// Disable DB update when using client/server
	if opt.RemoteAddr == "" {
		if err = initDB(opt); err != nil {
			if errors.Is(err, errSkipScan) {
				return nil
			}
			return xerrors.Errorf("DB error: %w", err)
		}
		defer db.Close()
	}

	kubeConfig, err := trivyk8s.GetKubeConfig()
	if err != nil {
		log.Fatal(err)
	}

	trivyk8s, err := trivyk8s.New(kubeConfig)
	if err != nil {
		log.Fatal(err)
	}

	k8sArtifacts, err := trivyk8s.ListArtifacts(ctx.Context, opt.KubernetesOption.Namespace)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	err = scanK8sImages(ctx, opt, cacheClient, k8sArtifacts)
	if err != nil {
		return xerrors.Errorf("scan kubernetes images error: %w", err)
	}

	err = scanK8sIac(ctx, opt, cacheClient, k8sArtifacts)
	if err != nil {
		return xerrors.Errorf("scan kubernetes iac error: %w", err)
	}

	return nil
}

func scanK8sImages(ctx *cli.Context, opt Option, cacheClient cache.Cache, artifacts []*artifacts.Artifact) error {
	// Disable the lock file scanning
	opt.DisabledAnalyzers = analyzer.TypeLockfiles

	scannerConfig, scannerOptions, err := initScannerConfig(ctx.Context, opt, cacheClient)
	if err != nil {
		return xerrors.Errorf("scanner config error: %w", err)
	}

	reports := make([]reportk8s.KubernetesReport, 0)
	for _, artifact := range artifacts {
		for _, image := range artifact.Images {
			report, err := k8sScan(ctx.Context, image, imageScanner, scannerConfig, scannerOptions)
			if err != nil {
				return xerrors.Errorf("scan error: %w", err)
			}

			report, err = filter(ctx.Context, opt, report)
			if err != nil {
				return xerrors.Errorf("filter error: %w", err)
			}

			reports = append(reports, reportk8s.KubernetesReport{
				Namespace: artifact.Namespace,
				Kind:      artifact.Kind,
				Name:      artifact.Name,
				Image:     image,
				Results:   report.Results,
			})
		}
	}

	reportk8s.PrintImagesReport(reports)

	return nil
}

func scanK8sIac(ctx *cli.Context, opt Option, cacheClient cache.Cache, artifacts []*artifacts.Artifact) error {
	// Disable OS and language analyzers
	opt.DisabledAnalyzers = append(analyzer.TypeOSes, analyzer.TypeLanguages...)

	// Scan only config files
	opt.VulnType = nil
	opt.SecurityChecks = []string{types.SecurityCheckConfig}

	// Skip downloading vulnerability DB
	opt.SkipDBUpdate = true

	scannerConfig, scannerOptions, err := initScannerConfig(ctx.Context, opt, cacheClient)

	tmpdir, err := ioutil.TempDir("", "trivy-iac")
	if err != nil {
		return xerrors.Errorf("create tmp folder error: %w", err)
	}
	defer os.RemoveAll(tmpdir)

	reports := make([]reportk8s.KubernetesReport, 0)

	for _, artifact := range artifacts {
		filename := filepath.Join(tmpdir, fmt.Sprintf("%s-%s-%s.yaml", artifact.Namespace, artifact.Kind, artifact.Name))
		file, err := os.Create(filename)
		if err != nil {
			return xerrors.Errorf("creating tmp file error: %w", err)
		}
		defer file.Close()

		err = artifact.WriteToFile(file)
		if err != nil {
			return xerrors.Errorf("error writing artifact to file: %w", err)
		}

		report, err := k8sScan(ctx.Context, file.Name(), filesystemStandaloneScanner, scannerConfig, scannerOptions)
		if err != nil {
			return xerrors.Errorf("scan error: %w", err)
		}

		report, err = filter(ctx.Context, opt, report)
		if err != nil {
			return xerrors.Errorf("filter error: %w", err)
		}

		reports = append(reports, reportk8s.KubernetesReport{
			Namespace: artifact.Namespace,
			Kind:      artifact.Kind,
			Name:      artifact.Name,
			Results:   report.Results,
		})
	}

	reportk8s.PrintImagesReport(reports)

	return nil
}

func k8sScan(ctx context.Context, target string, initializeScanner InitializeScanner, config ScannerConfig, opts types.ScanOptions) (types.Report, error) {
	config.Target = target
	s, cleanup, err := initializeScanner(ctx, config)
	if err != nil {
		// TODO: should exit?
		log.Logger.Errorf("Unexpected error during scanning %s: %s", config.Target, err)
		return types.Report{}, nil
	}
	defer cleanup()

	report, err := s.ScanArtifact(ctx, opts)
	if err != nil {
		return types.Report{}, xerrors.Errorf("image scan failed: %w", err)
	}
	return report, nil
}
