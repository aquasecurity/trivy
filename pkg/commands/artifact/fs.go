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

func filesystemScanner(ctx context.Context, dir string, ac cache.ArtifactCache, lac cache.LocalArtifactCache,
	_ time.Duration, disabled []analyzer.Type) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeFilesystemScanner(ctx, dir, ac, lac, disabled)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a filesystem scanner: %w", err)
	}
	return s, cleanup, nil
}

// FilesystemRun runs scan on filesystem
func FilesystemRun(ctx *cli.Context) error {
	c, err := NewConfig(ctx)
	if err != nil {
		return err
	}

	// initialize config
	if err = c.Init(); err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	return run(ctx.Context, c, filesystemScanner)
}
