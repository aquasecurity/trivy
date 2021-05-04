package artifact

import (
	"context"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/scanner"
)

func filesystemScanner(ctx context.Context, dir string, ac cache.ArtifactCache, lac cache.LocalArtifactCache,
	_ time.Duration, disabled []analyzer.Type, opt config.ScannerOption) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeFilesystemScanner(ctx, dir, ac, lac, disabled, opt)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a filesystem scanner: %w", err)
	}
	return s, cleanup, nil
}

// FilesystemRun runs scan on filesystem
func FilesystemRun(ctx *cli.Context) error {
	opt, err := NewOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	// initialize options
	if err = opt.Init(); err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	return Run(ctx.Context, opt, filesystemScanner, initFSCache)
}
