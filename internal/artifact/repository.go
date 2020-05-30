package artifact

import (
	"context"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/internal/artifact/config"
	"github.com/aquasecurity/trivy/pkg/scanner"
)

func repositoryScanner(ctx context.Context, dir string, ac cache.ArtifactCache, lac cache.LocalArtifactCache, timeout time.Duration) (
	scanner.Scanner, func(), error) {
	s, cleanup, err := initializeRepositoryScanner(ctx, dir, ac, lac)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a filesystem scanner: %w", err)
	}
	return s, cleanup, nil
}

func RepositoryRun(cliCtx *cli.Context) error {
	c, err := config.New(cliCtx)
	if err != nil {
		return err
	}

	// initialize config
	if err = c.Init(false); err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	return run(c, repositoryScanner)
}
