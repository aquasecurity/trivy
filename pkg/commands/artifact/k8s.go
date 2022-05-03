package artifact

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
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

	kubeConfig, err := k8s.GetKubeConfig()
	if err != nil {
		return xerrors.Errorf("get kubeconfig error: %w", err)
	}

	k8sDynamicClient, err := k8s.NewDynamicClient(kubeConfig)
	if err != nil {
		return xerrors.Errorf("failed to instantiate dynamic client: %w", err)
	}

	trivyk8s := trivyk8s.New(k8sDynamicClient)
	if len(opt.KubernetesOption.Namespace) > 0 {
		trivyk8s = trivyk8s.Namespace(opt.KubernetesOption.Namespace)
	}

	k8sArtifacts, err := trivyk8s.ListArtifacts(ctx.Context)
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

	reports := make([]KubernetesReport, 0)
	for _, artifact := range artifacts {
		for _, image := range artifact.Images {
			report, err := k8sScan(ctx.Context, image, imageScanner, scannerConfig, scannerOptions)

			// if an image failed to be scanned, we add the report as error and continue to scan other images
			if err != nil {
				reports = append(reports, KubernetesReport{
					Namespace: artifact.Namespace,
					Kind:      artifact.Kind,
					Name:      artifact.Name,
					Image:     image,
					Results:   report.Results,
					Error:     err,
				})

				continue
			}

			report, err = filter(ctx.Context, opt, report)
			if err != nil {
				return xerrors.Errorf("filter error: %w", err)
			}

			reports = append(reports, KubernetesReport{
				Namespace: artifact.Namespace,
				Kind:      artifact.Kind,
				Name:      artifact.Name,
				Image:     image,
				Results:   report.Results,
			})
		}
	}

	fmt.Printf("%v\n", reports)

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
	if err != nil {
		return xerrors.Errorf("scanner config error: %w", err)
	}

	reports := make([]KubernetesReport, 0)

	for _, artifact := range artifacts {
		file, err := createTempFile(artifact)

		report, err := k8sScan(ctx.Context, file.Name(), filesystemStandaloneScanner, scannerConfig, scannerOptions)
		if err != nil {
			return xerrors.Errorf("scan error: %w", err)
		}

		file.Close()
		err = os.Remove(file.Name())
		if err != nil {
			log.Logger.Errorf("failed to delete temp file %s:%w:", file.Name(), err)
		}

		report, err = filter(ctx.Context, opt, report)
		if err != nil {
			return xerrors.Errorf("filter error: %w", err)
		}

		reports = append(reports, KubernetesReport{
			Namespace: artifact.Namespace,
			Kind:      artifact.Kind,
			Name:      artifact.Name,
			Results:   report.Results,
		})
	}

	fmt.Printf("%v\n", reports)

	return nil
}

func k8sScan(ctx context.Context, target string, initializeScanner InitializeScanner, config ScannerConfig, opts types.ScanOptions) (types.Report, error) {
	config.Target = target
	s, cleanup, err := initializeScanner(ctx, config)
	if err != nil {
		log.Logger.Errorf("Unexpected error during scanning %s: %s", config.Target, err)
		return types.Report{}, err
	}
	defer cleanup()

	report, err := s.ScanArtifact(ctx, opts)
	if err != nil {
		return types.Report{}, xerrors.Errorf("artifact scan failed: %w", err)
	}
	return report, nil
}

type KubernetesReport struct {
	Namespace string
	Kind      string
	Name      string
	Image     string
	Results   types.Results
	Error     error
}

func createTempFile(artifact *artifacts.Artifact) (*os.File, error) {
	filename := fmt.Sprintf("%s-%s-%s-r*.yaml", artifact.Namespace, artifact.Kind, artifact.Name)
	file, err := os.CreateTemp("", filename)
	if err != nil {
		return nil, xerrors.Errorf("creating tmp file error: %w", err)
	}

	fmt.Println("debugging", file.Name())

	// TODO: marshal and return as byte can be on the trivy-kubernetes library
	data, err := yaml.Marshal(artifact.RawResource)
	if err != nil {
		return nil, xerrors.Errorf("marshalling resource error: %w", err)
	}

	_, err = file.Write(data)
	if err != nil {
		return nil, xerrors.Errorf("writing tmp file error: %w", err)
	}

	return file, nil
}
