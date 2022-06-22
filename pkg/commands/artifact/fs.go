package artifact

import (
	"context"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/scanner"
)

// filesystemStandaloneScanner initializes a filesystem scanner in standalone mode
func filesystemStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeFilesystemScanner(ctx, conf.Target, conf.ArtifactCache, conf.LocalArtifactCache, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a filesystem scanner: %w", err)
	}
	return s, cleanup, nil
}

// filesystemRemoteScanner initializes a filesystem scanner in client/server mode
func filesystemRemoteScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeRemoteFilesystemScanner(ctx, conf.Target, conf.ArtifactCache, conf.RemoteOption, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a filesystem scanner: %w", err)
	}
	return s, cleanup, nil
}

// FilesystemRun runs scan on filesystem for language-specific dependencies and config files
func FilesystemRun(ctx *cli.Context) error {
	return Run(ctx, filesystemArtifact)
}

// RootfsRun runs scan on rootfs.
func RootfsRun(ctx *cli.Context) error {
	return Run(ctx, rootfsArtifact)
}
