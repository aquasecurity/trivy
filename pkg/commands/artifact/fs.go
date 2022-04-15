package artifact

import (
	"context"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/scanner"
)

// filesystemStandaloneScanner initializes a filesystem scanner in standalone mode
func filesystemStandaloneScanner(ctx context.Context, conf scannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeFilesystemScanner(ctx, conf.Target, conf.ArtifactCache, conf.LocalArtifactCache, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a filesystem scanner: %w", err)
	}
	return s, cleanup, nil
}

// filesystemRemoteScanner initializes a filesystem scanner in client/server mode
func filesystemRemoteScanner(ctx context.Context, conf scannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeRemoteFilesystemScanner(ctx, conf.Target, conf.ArtifactCache, conf.RemoteOption, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a filesystem scanner: %w", err)
	}
	return s, cleanup, nil
}

// FilesystemRun runs scan on filesystem for language-specific dependencies and config files
func FilesystemRun(ctx *cli.Context) error {
	opt, err := initOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	// Disable the individual package scanning
	opt.DisabledAnalyzers = analyzer.TypeIndividualPkgs
	//opt.DisabledAnalyzers = append(opt.DisabledAnalyzers, analyzer.TypeSecret)

	// client/server mode
	if opt.RemoteAddr != "" {
		return Run(ctx.Context, opt, filesystemRemoteScanner, initCache)
	}

	// standalone mode
	return Run(ctx.Context, opt, filesystemStandaloneScanner, initCache)
}

// RootfsRun runs scan on rootfs.
func RootfsRun(ctx *cli.Context) error {
	opt, err := initOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	// Disable the lock file scanning
	opt.DisabledAnalyzers = analyzer.TypeLockfiles

	// client/server mode
	if opt.RemoteAddr != "" {
		return Run(ctx.Context, opt, filesystemRemoteScanner, initCache)
	}

	// standalone mode
	return Run(ctx.Context, opt, filesystemStandaloneScanner, initCache)
}
