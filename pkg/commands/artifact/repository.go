package artifact

import (
	"context"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
)

// filesystemStandaloneScanner initializes a repository scanner in standalone mode
func repositoryScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeRepositoryScanner(ctx, conf.Target, conf.ArtifactCache, conf.LocalArtifactCache, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a filesystem scanner: %w", err)
	}
	return s, cleanup, nil
}

// RepositoryRun runs scan on repository
func RepositoryRun(ctx *cli.Context) error {
	opt, err := initOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	// Do not scan OS packages
	opt.VulnType = []string{types.VulnTypeLibrary}

	// Disable the OS analyzers and individual package analyzers
	opt.DisabledAnalyzers = append(analyzer.TypeIndividualPkgs, analyzer.TypeOSes...)

	return Run(ctx.Context, opt, repositoryScanner, initCache)
}
