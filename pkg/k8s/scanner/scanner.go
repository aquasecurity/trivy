package scanner

import (
	"context"
	"io"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
)

type Scanner struct {
	cluster string
	runner  cmd.Runner
	opt     cmd.Option
}

func NewScanner(cluster string, runner cmd.Runner, opt cmd.Option) *Scanner {
	return &Scanner{cluster, runner, opt}
}

func (s *Scanner) Scan(ctx context.Context, artifacts []*artifacts.Artifact) (report.Report, error) {
	// progress bar
	bar := pb.StartNew(len(artifacts))
	if s.opt.NoProgress {
		bar.SetWriter(io.Discard)
	}
	defer bar.Finish()

	var vulns, misconfigs []report.Resource

	// disable logs before scanning
	err := log.InitLogger(s.opt.Debug, true)
	if err != nil {
		return report.Report{}, xerrors.Errorf("logger error: %w", err)
	}

	// enable log, this is done in a defer function,
	// to enable logs even when the function returns earlier
	// due to an error
	defer func() {
		err = log.InitLogger(s.opt.Debug, false)
		if err != nil {
			// we use log.Fatal here because the error was to enable the logger
			log.Fatal(xerrors.Errorf("can't enable logger error: %w", err))
		}
	}()

	// Loops once over all artifacts, and execute scanners as necessary. Not every artifacts has an image,
	// so image scanner is not always executed.
	for _, artifact := range artifacts {
		bar.Increment()

		if slices.Contains(s.opt.SecurityChecks, types.SecurityCheckVulnerability) {
			resources, err := s.scanVulns(ctx, artifact)
			if err != nil {
				return report.Report{}, xerrors.Errorf("scanning vulnerabilities error: %w", err)
			}
			vulns = append(vulns, resources...)
		}

		if slices.Contains(s.opt.SecurityChecks, types.SecurityCheckConfig) {
			resource, err := s.scanMisconfigs(ctx, artifact)
			if err != nil {
				return report.Report{}, xerrors.Errorf("scanning misconfigurations error: %w", err)
			}
			misconfigs = append(misconfigs, resource)
		}
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

		s.opt.Target = image

		imageReport, err := s.runner.ScanImage(ctx, s.opt)

		if err != nil {
			log.Logger.Debugf("failed to scan image %s: %s", image, err)
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

	s.opt.Target = configFile

	configReport, err := s.runner.ScanFilesystem(ctx, s.opt)
	//remove config file after scanning
	removeFile(configFile)
	if err != nil {
		log.Logger.Debugf("failed to scan config %s/%s: %s", artifact.Kind, artifact.Name, err)
		return report.CreateResource(artifact, configReport, err), err
	}

	return s.filter(ctx, configReport, artifact)
}

func (s *Scanner) filter(ctx context.Context, r types.Report, artifact *artifacts.Artifact) (report.Resource, error) {
	r, err := s.runner.Filter(ctx, s.opt, r)
	if err != nil {
		return report.Resource{}, xerrors.Errorf("filter error: %w", err)
	}

	return report.CreateResource(artifact, r, nil), nil
}
