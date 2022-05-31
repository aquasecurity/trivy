package k8s

import (
	"context"
	"io"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
)

type scanner struct {
	cluster string
	runner  *cmd.Runner
	opt     cmd.Option
}

func (s *scanner) run(ctx context.Context, artifacts []*artifacts.Artifact) (Report, error) {
	// progress bar
	bar := pb.StartNew(len(artifacts))
	if s.opt.NoProgress {
		bar.SetWriter(io.Discard)
	}
	defer bar.Finish()

	var vulns, misconfigs []Resource

	// disable logs before scanning
	err := log.InitLogger(s.opt.Debug, true)
	if err != nil {
		return Report{}, xerrors.Errorf("logger error: %w", err)
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
				return Report{}, xerrors.Errorf("scanning vulnerabilities error: %w", err)
			}
			vulns = append(vulns, resources...)
		}

		if slices.Contains(s.opt.SecurityChecks, types.SecurityCheckConfig) {
			resource, err := s.scanMisconfigs(ctx, artifact)
			if err != nil {
				return Report{}, xerrors.Errorf("scanning misconfigurations error: %w", err)
			}
			misconfigs = append(misconfigs, resource)
		}
	}

	return Report{
		SchemaVersion:     0,
		ClusterName:       s.cluster,
		Vulnerabilities:   vulns,
		Misconfigurations: misconfigs,
	}, nil
}

func (s *scanner) scanVulns(ctx context.Context, artifact *artifacts.Artifact) ([]Resource, error) {
	resources := make([]Resource, 0, len(artifact.Images))

	for _, image := range artifact.Images {

		s.opt.Target = image

		imageReport, err := s.runner.ScanImage(ctx, s.opt)

		if err != nil {
			log.Logger.Debugf("failed to scan image %s: %s", image, err)
			resources = append(resources, createResource(artifact, imageReport, err))
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

func (s *scanner) scanMisconfigs(ctx context.Context, artifact *artifacts.Artifact) (Resource, error) {
	configFile, err := createTempFile(artifact)
	if err != nil {
		return Resource{}, xerrors.Errorf("scan error: %w", err)
	}

	s.opt.Target = configFile

	configReport, err := s.runner.ScanFilesystem(ctx, s.opt)
	//remove config file after scanning
	removeFile(configFile)
	if err != nil {
		log.Logger.Debugf("failed to scan config %s/%s: %s", artifact.Kind, artifact.Name, err)
		return createResource(artifact, configReport, err), err
	}

	return s.filter(ctx, configReport, artifact)
}

func (s *scanner) filter(ctx context.Context, report types.Report, artifact *artifacts.Artifact) (Resource, error) {
	report, err := s.runner.Filter(ctx, s.opt, report)
	if err != nil {
		return Resource{}, xerrors.Errorf("filter error: %w", err)
	}

	return createResource(artifact, report, nil), nil
}
