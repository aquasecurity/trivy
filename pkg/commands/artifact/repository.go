package artifact

import (
	"context"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/scanner"
)

func repositoryScanner(ctx context.Context, dir string, ac cache.ArtifactCache, lac cache.LocalArtifactCache,
	_ time.Duration, artifactOpt artifact.Option, scannerOpt config.ScannerOption) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeRepositoryScanner(ctx, dir, ac, lac, artifactOpt, scannerOpt)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a filesystem scanner: %w", err)
	}
	return s, cleanup, nil
}

// RepositoryRun runs scan on repository
func RepositoryRun(ctx *cli.Context) error {
	opt, err := NewOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	// initialize options
	if err = opt.Init(); err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	return Run(ctx.Context, opt, repositoryScanner, initFSCache)
}
