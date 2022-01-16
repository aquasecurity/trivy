package artifact

import (
	"context"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
)

func archiveScanner(ctx context.Context, input string, ac cache.ArtifactCache, lac cache.LocalArtifactCache,
	_ bool, artifactOpt artifact.Option, scannerOpt config.ScannerOption) (scanner.Scanner, func(), error) {
	s, err := initializeArchiveScanner(ctx, input, ac, lac, artifactOpt, scannerOpt)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize the archive scanner: %w", err)
	}
	return s, func() {}, nil
}

func dockerScanner(ctx context.Context, imageName string, ac cache.ArtifactCache, lac cache.LocalArtifactCache,
	insecure bool, artifactOpt artifact.Option, scannerOpt config.ScannerOption) (scanner.Scanner, func(), error) {
	dockerOpt, err := types.GetDockerOption(insecure)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	s, cleanup, err := initializeDockerScanner(ctx, imageName, ac, lac, dockerOpt, artifactOpt, scannerOpt)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a docker scanner: %w", err)
	}
	return s, cleanup, nil
}

// ImageRun runs scan on docker image
func ImageRun(ctx *cli.Context) error {
	opt, err := initOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	// Disable the lock file scanning
	opt.DisabledAnalyzers = analyzer.TypeLockfiles

	if opt.Input != "" {
		// scan tar file
		return Run(ctx.Context, opt, archiveScanner, initFSCache)
	}

	return Run(ctx.Context, opt, dockerScanner, initFSCache)
}
