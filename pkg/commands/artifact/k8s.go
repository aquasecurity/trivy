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

	// list all kubernetes scannable artifacts
	k8sArtifacts, err := trivyk8s.ListArtifacts(ctx.Context)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	resources, err := k8sRun(ctx, opt, cacheClient, k8sArtifacts)
	if err != nil {
		return xerrors.Errorf("k8s scan error: %w", err)
	}

	clusterName, err := k8s.GetCurrentContext()
	if err != nil {
		return xerrors.Errorf("failed to get k8s current context: %w", err)
	}

	report := types.K8sReport{
		SchemaVersion: 0,
		ClusterName:   clusterName,
		Resources:     resources,
	}

	if err = k8sReport.Write(report, pkgReport.Option{
		Format: opt.Format,
		Output: opt.Output,
	}); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	return nil
}

func k8sRun(ctx *cli.Context, opt Option, cacheClient cache.Cache, k8sArtifacts []*artifacts.Artifact) ([]types.K8sResource, error) {
	// image scanner configurations
	imageScannerConfig, imageScannerOptions, err := initImageScannerConfig(ctx.Context, opt, cacheClient)
	if err != nil {
		return nil, xerrors.Errorf("scanner config error: %w", err)
	}

	// config scanner configurations
	configScannerConfig, configScannerOptions, err := initConfigScannerConfig(ctx.Context, opt, cacheClient)
	if err != nil {
		return nil, xerrors.Errorf("scanner config error: %w", err)
	}

	resources := make([]types.K8sResource, 0)

	// Loops once over all artifacts, and execute scanners as necessary. Not every artifacts has an image,
	// so image scanner is not always executed.
	for _, artifact := range k8sArtifacts {
		reports := make([]types.Report, 0)

		// scan images if present
		for _, image := range artifact.Images {
			report, err := k8sScan(ctx.Context, image, imageScanner, imageScannerConfig, imageScannerOptions)
			if err != nil {
				// TODO(josedonizetti): should not ignore image on the report, it should display there was an error
				log.Logger.Errorf("failed to scan image %s:%w:", image, err)
				continue
			}
			reports = append(reports, report)
		}

		report, err := k8sScanConfig(ctx, configScannerConfig, configScannerOptions, artifact)
		if err != nil {
			return nil, xerrors.Errorf("failed to scan k8s config: %w", err)
		}
		reports = append(reports, report)

		// apply filters on all reports
		for i, report := range reports {
			report, err = filter(ctx.Context, opt, report)
			if err != nil {
				return nil, xerrors.Errorf("filter error: %w", err)
			}
			reports[i] = report
		}

		resources = append(resources, newK8sResource(artifact, reports))
	}

	return resources, nil
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

func k8sScanConfig(ctx *cli.Context, config ScannerConfig, opts types.ScanOptions, a *artifacts.Artifact) (types.Report, error) {
	file, err := createTempFile(a)
	if err != nil {
		return types.Report{}, xerrors.Errorf("scan error: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Logger.Errorf("failed to delete temp file %s:%w:", file.Name(), err)
		}
	}()

	report, err := k8sScan(ctx.Context, file.Name(), filesystemStandaloneScanner, config, opts)
	if err != nil {
		return types.Report{}, xerrors.Errorf("scan error: %w", err)
	}

	if err := os.Remove(file.Name()); err != nil {
		log.Logger.Errorf("failed to delete temp file %s:%w:", file.Name(), err)
	}

	return report, nil
}

func k8sScan(ctx context.Context, target string, initializeScanner InitializeScanner, config ScannerConfig, opts types.ScanOptions) (types.Report, error) {
	config.Target = target
	s, cleanup, err := initializeScanner(ctx, config)
	if err != nil {
		log.Logger.Errorf("unexpected error during scanning %s: %s", config.Target, err)
		return types.Report{}, err
	}
	defer cleanup()

	report, err := s.ScanArtifact(ctx, opts)
	if err != nil {
		return types.Report{}, xerrors.Errorf("artifact scan failed: %w", err)
	}
	return report, nil
}

func createTempFile(artifact *artifacts.Artifact) (*os.File, error) {
	filename := fmt.Sprintf("%s-%s-%s-*.yaml", artifact.Namespace, artifact.Kind, artifact.Name)
	file, err := os.CreateTemp("", filename)
	if err != nil {
		return nil, xerrors.Errorf("creating tmp file error: %w", err)
	}

	// TODO(josedonizetti): marshal and return as byte slice should be on the trivy-kubernetes library?
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

func newK8sResource(artifact *artifacts.Artifact, reports []types.Report) types.K8sResource {
	results := make([]types.Result, 0)

	// merge all results
	for _, report := range reports {
		for _, result := range report.Results {
			// if resource is a kubernetes file fix the target name,
			// to avoid showing the temp file that was removed.
			if result.Type == "kubernetes" {
				result.Target = fmt.Sprintf("%s/%s", artifact.Kind, artifact.Name)
			}
			results = append(results, result)
		}
	}

	return types.K8sResource{
		Namespace: artifact.Namespace,
		Kind:      artifact.Kind,
		Name:      artifact.Name,
		Results:   results,
	}
}
