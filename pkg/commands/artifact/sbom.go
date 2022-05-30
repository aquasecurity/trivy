package artifact

import (
	"context"

	"github.com/urfave/cli/v2"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
)

// SbomRun runs generates sbom for image and package artifacts
func SbomRun(ctx *cli.Context) error {
	opt, err := InitOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	artifactType := ArtifactType(opt.SbomOption.ArtifactType)
	if !slices.Contains(supportedArtifactTypes, artifactType) {
		return xerrors.Errorf(`"--artifact-type" must be %q`, supportedArtifactTypes)
	}

	// Pass the specified image archive via "--input".
	if artifactType == imageArchiveArtifact {
		opt.Input = opt.Target
	}

	// Scan the relevant dependencies
	opt.ReportOption.VulnType = []string{types.VulnTypeOS, types.VulnTypeLibrary}
	opt.ReportOption.SecurityChecks = []string{types.SecurityCheckVulnerability}

	return run(ctx.Context, opt, artifactType)
}

func cycloneDXStandaloneScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeCycloneDXScanner(ctx, conf.Target, conf.ArtifactCache, conf.LocalArtifactCache, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a cycloneDX scanner: %w", err)
	}
	return s, cleanup, nil
}

func cycloneDXRemoteScanner(ctx context.Context, conf ScannerConfig) (scanner.Scanner, func(), error) {
	s, cleanup, err := initializeRemoteCycloneDXScanner(ctx, conf.Target, conf.ArtifactCache, conf.RemoteOption, conf.ArtifactOption)
	if err != nil {
		return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a cycloneDX scanner: %w", err)
	}
	return s, cleanup, nil
}
