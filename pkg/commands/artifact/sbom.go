package artifact

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

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
