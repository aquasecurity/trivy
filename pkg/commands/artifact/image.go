package artifact

import (
	"context"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/scanner"
)

func archiveScanner(ctx context.Context, input string, ac cache.ArtifactCache, lac cache.LocalArtifactCache,
	timeout time.Duration, disabled []analyzer.Type) (scanner.Scanner, func(), error) {
	s, err := initializeArchiveScanner(ctx, input, ac, lac, timeout, disabled)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize the archive scanner: %w", err)
	}
	return s, func() {}, nil
}

func dockerScanner(ctx context.Context, imageName string, ac cache.ArtifactCache, lac cache.LocalArtifactCache,
	timeout time.Duration, disabled []analyzer.Type) (
	scanner.Scanner, func(), error) {
	s, cleanup, err := initializeDockerScanner(ctx, imageName, ac, lac, timeout, disabled)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a docker scanner: %w", err)
	}
	return s, cleanup, nil
}

// ImageRun runs scan on docker image
func ImageRun(ctx *cli.Context) error {
	c, err := NewConfig(ctx)
	if err != nil {
		return err
	}

	// initialize config
	if err = c.Init(); err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	if c.Input != "" {
		// scan tar file
		return run(ctx.Context, c, archiveScanner)
	}

	return run(ctx.Context, c, dockerScanner)
}
