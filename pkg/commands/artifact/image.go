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

func archiveScanner(ctx context.Context, input string, ac cache.ArtifactCache, lac cache.LocalArtifactCache,
	timeout time.Duration, disabled []analyzer.Type, opt config.ScannerOption) (scanner.Scanner, func(), error) {
	s, err := initializeArchiveScanner(ctx, input, ac, lac, timeout, disabled, opt)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize the archive scanner: %w", err)
	}
	return s, func() {}, nil
}

func dockerScanner(ctx context.Context, imageName string, ac cache.ArtifactCache, lac cache.LocalArtifactCache,
	timeout time.Duration, disabled []analyzer.Type, opt config.ScannerOption) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeDockerScanner(ctx, imageName, ac, lac, timeout, disabled, opt)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a docker scanner: %w", err)
	}
	return s, cleanup, nil
}

// ImageRun runs scan on docker image
func ImageRun(cliCtx *cli.Context) error {
	opt, err := NewOption(cliCtx)
	if err != nil {
		return err
	}

	// initialize options
	if err := opt.Init(); err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	if opt.Input != "" {
		// scan tar file
		return Run(opt, archiveScanner, initFSCache)
	}

	return Run(opt, dockerScanner, initFSCache)
}
