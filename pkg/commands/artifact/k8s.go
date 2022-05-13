package artifact

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cheggaaa/pb/v3"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"

	"github.com/aquasecurity/trivy/pkg/log"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
	k8sReport "github.com/aquasecurity/trivy/pkg/report/k8s"
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

	cluster, err := k8s.GetCluster()
	if err != nil {
		return xerrors.Errorf("get k8s cluster: %w", err)
	}

	trivyk8s := trivyk8s.New(cluster).Namespace(opt.KubernetesOption.Namespace)

	// list all kubernetes scannable artifacts
	k8sArtifacts, err := trivyk8s.ListArtifacts(ctx.Context)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	report, err := k8sRun(ctx, opt, cacheClient, k8sArtifacts)
	if err != nil {
		return xerrors.Errorf("k8s scan error: %w", err)
	}
	report.ClusterName = cluster.GetCurrentContext()

	if err = k8sReport.Write(report, pkgReport.Option{
		Format: opt.KubernetesOption.ReportFormat, // for now json is the default
		Output: opt.Output,
	}, opt.Severities); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	exit(opt, report.Failed())

	return nil
}

func k8sRun(cliContext *cli.Context, opt Option, cacheClient cache.Cache, k8sArtifacts []*artifacts.Artifact) (k8sReport.Report, error) {
	ctx, cancel := context.WithTimeout(cliContext.Context, opt.Timeout)
	defer cancel()

	// progress bar
	bar := pb.StartNew(len(k8sArtifacts))
	if opt.NoProgress {
		bar.SetWriter(io.Discard)
	}
	defer bar.Finish()

	// image scanner configurations
	imageScannerConfig, imageScannerOptions, err := initImageScannerConfig(ctx, opt, cacheClient)
	if err != nil {
		return k8sReport.Report{}, xerrors.Errorf("scanner config error: %w", err)
	}

	// config scanner configurations
	configScannerConfig, configScannerOptions, err := initConfigScannerConfig(ctx, opt, cacheClient)
	if err != nil {
		return k8sReport.Report{}, xerrors.Errorf("scanner config error: %w", err)
	}

	vulns := make([]k8sReport.Resource, 0)
	misconfigs := make([]k8sReport.Resource, 0)

	// Loops once over all artifacts, and execute scanners as necessary. Not every artifacts has an image,
	// so image scanner is not always executed.
	for _, artifact := range k8sArtifacts {
		bar.Increment()

		// scan images if present
		for _, image := range artifact.Images {
			imageReport, err := k8sScan(ctx, image, imageScanner, imageScannerConfig, imageScannerOptions)
			if err != nil {
				// add error to report
				log.Logger.Debugf("failed to scan image %s: %s", image, err)
				vulns = append(vulns, newK8sResource(artifact, imageReport, err))
				continue
			}

			imageReport, err = filter(ctx, opt, imageReport)
			if err != nil {
				return k8sReport.Report{}, xerrors.Errorf("filter error: %w", err)
			}

			vulns = append(vulns, newK8sResource(artifact, imageReport, nil))
		}

		// scan configurations
		configReport, err := k8sScanConfig(ctx, configScannerConfig, configScannerOptions, artifact)
		if err != nil {
			// add error to report
			log.Logger.Debugf("failed to scan config %s/%s: %s", artifact.Kind, artifact.Name, err)
			misconfigs = append(misconfigs, newK8sResource(artifact, configReport, err))
		}

		configReport, err = filter(ctx, opt, configReport)
		if err != nil {
			return k8sReport.Report{}, xerrors.Errorf("filter error: %w", err)
		}

		misconfigs = append(misconfigs, newK8sResource(artifact, configReport, nil))
	}

	return k8sReport.Report{
		SchemaVersion:     0,
		Vulnerabilities:   vulns,
		Misconfigurations: misconfigs,
	}, nil
}

func initImageScannerConfig(ctx context.Context, opt Option, cacheClient cache.Cache) (ScannerConfig, types.ScanOptions, error) {
	// Disable the lock file scanning
	opt.DisabledAnalyzers = analyzer.TypeLockfiles

	return initScannerConfig(ctx, opt, cacheClient)
}

func initConfigScannerConfig(ctx context.Context, opt Option, cacheClient cache.Cache) (ScannerConfig, types.ScanOptions, error) {
	// Disable OS and language analyzers
	opt.DisabledAnalyzers = append(analyzer.TypeOSes, analyzer.TypeLanguages...)

	// Scan only config files
	opt.VulnType = nil
	opt.SecurityChecks = []string{types.SecurityCheckConfig}

	// Skip downloading vulnerability DB
	opt.SkipDBUpdate = true

	return initScannerConfig(ctx, opt, cacheClient)
}

func k8sScanConfig(ctx context.Context, config ScannerConfig, opts types.ScanOptions, a *artifacts.Artifact) (types.Report, error) {
	fileName, err := createTempFile(a)
	if err != nil {
		return types.Report{}, xerrors.Errorf("scan error: %w", err)
	}
	defer removeFile(fileName)

	report, err := k8sScan(ctx, fileName, filesystemStandaloneScanner, config, opts)
	if err != nil {
		return types.Report{}, xerrors.Errorf("scan error: %w", err)
	}

	return report, nil
}

func k8sScan(ctx context.Context, target string, initializeScanner InitializeScanner, config ScannerConfig, opts types.ScanOptions) (types.Report, error) {
	config.Target = target
	s, cleanup, err := initializeScanner(ctx, config)
	if err != nil {
		log.Logger.Debugf("unexpected error during scanning %s: %s", config.Target, err)
		return types.Report{}, err
	}
	defer cleanup()

	report, err := s.ScanArtifact(ctx, opts)
	if err != nil {
		return types.Report{}, xerrors.Errorf("artifact scan failed: %w", err)
	}
	return report, nil
}

func createTempFile(artifact *artifacts.Artifact) (string, error) {
	filename := fmt.Sprintf("%s-%s-%s-*.yaml", artifact.Namespace, artifact.Kind, artifact.Name)

	file, err := os.CreateTemp("", filename)
	if err != nil {
		return "", xerrors.Errorf("creating tmp file error: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Logger.Errorf("failed to close temp file %s: %s:", file.Name(), err)
		}
	}()

	// TODO(josedonizetti): marshal and return as byte slice should be on the trivy-kubernetes library?
	data, err := yaml.Marshal(artifact.RawResource)
	if err != nil {
		removeFile(filename)
		return "", xerrors.Errorf("marshaling resource error: %w", err)
	}

	_, err = file.Write(data)
	if err != nil {
		removeFile(filename)
		return "", xerrors.Errorf("writing tmp file error: %w", err)
	}

	return file.Name(), nil
}

func newK8sResource(artifact *artifacts.Artifact, report types.Report, err error) k8sReport.Resource {
	results := make([]types.Result, 0, len(report.Results))
	// fix target name
	for _, result := range report.Results {
		// if resource is a kubernetes file fix the target name,
		// to avoid showing the temp file that was removed.
		if result.Type == "kubernetes" {
			result.Target = fmt.Sprintf("%s/%s", artifact.Kind, artifact.Name)
		}
		results = append(results, result)
	}

	k8sreport := k8sReport.Resource{
		Namespace: artifact.Namespace,
		Kind:      artifact.Kind,
		Name:      artifact.Name,
		Results:   results,
	}

	// if there was any error during the scan
	if err != nil {
		k8sreport.Error = err.Error()
	}

	return k8sreport
}

func removeFile(filename string) {
	if err := os.Remove(filename); err != nil {
		log.Logger.Errorf("failed to remove temp file %s: %s:", filename, err)
	}
}
