package scanner

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/parallel"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Scanner struct {
	cluster string
	runner  cmd.Runner
	opts    flag.Options
}

func NewScanner(cluster string, runner cmd.Runner, opts flag.Options) *Scanner {
	return &Scanner{
		cluster,
		runner,
		opts,
	}
}

func (s *Scanner) Scan(ctx context.Context, artifactsData []*artifacts.Artifact) (report.Report, error) {

	// disable logs before scanning
	err := log.InitLogger(s.opts.Debug, true)
	if err != nil {
		return report.Report{}, xerrors.Errorf("logger error: %w", err)
	}

	// enable log, this is done in a defer function,
	// to enable logs even when the function returns earlier
	// due to an error
	defer func() {
		err = log.InitLogger(s.opts.Debug, false)
		if err != nil {
			// we use log.Fatal here because the error was to enable the logger
			log.Fatal(xerrors.Errorf("can't enable logger error: %w", err))
		}
	}()
	var vulns, misconfigs []report.Resource

	type scanResult struct {
		vulns     []report.Resource
		misconfig report.Resource
	}

	onItem := func(artifact *artifacts.Artifact) (scanResult, error) {
		scanResults := scanResult{}
		if s.opts.Scanners.AnyEnabled(types.VulnerabilityScanner, types.SecretScanner) {
			vulns, err := s.scanVulns(ctx, artifact)
			if err != nil {
				return scanResult{}, xerrors.Errorf("scanning vulnerabilities error: %w", err)
			}
			scanResults.vulns = vulns
		}
		if local.ShouldScanMisconfigOrRbac(s.opts.Scanners) {
			misconfig, err := s.scanMisconfigs(ctx, artifact)
			if err != nil {
				return scanResult{}, xerrors.Errorf("scanning misconfigurations error: %w", err)
			}
			scanResults.misconfig = misconfig
		}
		return scanResults, nil
	}

	onResult := func(result scanResult) error {
		vulns = append(vulns, result.vulns...)
		misconfigs = append(misconfigs, result.misconfig)
		return nil
	}

	p := parallel.NewPipeline(s.opts.Parallel, true, artifactsData, onItem, onResult)
	err = p.Do(ctx)
	if err != nil {
		return report.Report{}, err
	}

	return report.Report{
		SchemaVersion:     0,
		ClusterName:       s.cluster,
		Vulnerabilities:   vulns,
		Misconfigurations: misconfigs,
	}, nil
}

func (s *Scanner) scanVulns(ctx context.Context, artifact *artifacts.Artifact) ([]report.Resource, error) {
	resources := make([]report.Resource, 0, len(artifact.Images))

	for _, image := range artifact.Images {

		s.opts.Target = image

		imageReport, err := s.runner.ScanImage(ctx, s.opts)

		if err != nil {
			log.Logger.Warnf("failed to scan image %s: %s", image, err)
			resources = append(resources, report.CreateResource(artifact, imageReport, err))
			continue
		}

		resource, err := s.filter(ctx, imageReport, artifact)
		if err != nil {
			return nil, xerrors.Errorf("filter error: %w", err)
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

func (s *Scanner) scanMisconfigs(ctx context.Context, artifact *artifacts.Artifact) (report.Resource, error) {
	configFile, err := createTempFile(artifact)
	if err != nil {
		return report.Resource{}, xerrors.Errorf("scan error: %w", err)
	}

	s.opts.Target = configFile

	configReport, err := s.runner.ScanFilesystem(ctx, s.opts)
	//remove config file after scanning
	removeFile(configFile)
	if err != nil {
		log.Logger.Debugf("failed to scan config %s/%s: %s", artifact.Kind, artifact.Name, err)
		return report.CreateResource(artifact, configReport, err), err
	}

	return s.filter(ctx, configReport, artifact)
}
func (s *Scanner) filter(ctx context.Context, r types.Report, artifact *artifacts.Artifact) (report.Resource, error) {
	var err error
	r, err = s.runner.Filter(ctx, s.opts, r)
	if err != nil {
		return report.Resource{}, xerrors.Errorf("filter error: %w", err)
	}
	return report.CreateResource(artifact, r, nil), nil
}
