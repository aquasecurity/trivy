package artifact

import (
	"context"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/internal/artifact/config"
	"github.com/aquasecurity/trivy/pkg/scanner"
)

func repositoryScanner(ctx context.Context, dir string, ac cache.ArtifactCache, lac cache.LocalArtifactCache,
	_ time.Duration, disabled []analyzer.Type) (
	scanner.Scanner, func(), error) {
	s, cleanup, err := initializeRepositoryScanner(ctx, dir, ac, lac, disabled)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a filesystem scanner: %w", err)
	}
	return s, cleanup, nil
}

// RepositoryRun runs scan on repository
func RepositoryRun(cliCtx *cli.Context) error {
	c, err := config.New(cliCtx)
	if err != nil {
		return err
	}

	// initialize config
	if err = c.Init(); err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	return run(c, repositoryScanner)
}
