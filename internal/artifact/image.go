package artifact

import (
	"context"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/internal/artifact/config"
	artifact "github.com/aquasecurity/trivy/internal/config"
	"github.com/aquasecurity/trivy/pkg/scanner"
)

func archiveScanner(ctx context.Context, input string, ac cache.ArtifactCache, lac cache.LocalArtifactCache, timeout time.Duration) (
	scanner.Scanner, func(), error) {
	s, err := initializeArchiveScanner(ctx, input, ac, lac, timeout)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize the archive scanner: %w", err)
	}
	return s, func() {}, nil
}

func dockerScanner(ctx context.Context, imageName string, ac cache.ArtifactCache, lac cache.LocalArtifactCache, timeout time.Duration) (
	scanner.Scanner, func(), error) {
	s, cleanup, err := initializeDockerScanner(ctx, imageName, ac, lac, timeout)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a docker scanner: %w", err)
	}
	return s, cleanup, nil
}

func ImageRun(cliCtx *cli.Context) error {
	c, err := config.New(cliCtx)
	if err != nil {
		return err
	}

	// initialize config
	err = c.Init(true)
	if xerrors.Is(err, artifact.ErrNoTarget) {
		return nil
	} else if err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	if c.Input != "" {
		// scan tar file
		return run(c, archiveScanner)
	}

	return run(c, dockerScanner)
}
