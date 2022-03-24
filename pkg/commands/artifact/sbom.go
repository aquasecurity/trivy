package artifact

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/types"
)

type ArtifactType string

const (
	containerImageArtifact ArtifactType = "image"
	filesystemArtifact     ArtifactType = "fs"
	repositoryArtifact     ArtifactType = "repo"
	imageArchiveArtifact   ArtifactType = "archive"
)

var artifactTypes = map[ArtifactType]struct {
	initializer      InitializeScanner
	disableAnalyzers []analyzer.Type
}{
	containerImageArtifact: {
		initializer:      imageScanner,
		disableAnalyzers: analyzer.TypeLockfiles,
	},
	filesystemArtifact: {
		initializer:      filesystemStandaloneScanner,
		disableAnalyzers: analyzer.TypeIndividualPkgs,
	},
	repositoryArtifact: {
		initializer:      repositoryScanner,
		disableAnalyzers: analyzer.TypeIndividualPkgs,
	},
	imageArchiveArtifact: {
		initializer:      archiveScanner,
		disableAnalyzers: analyzer.TypeLockfiles,
	},
}

// SbomRun runs generates sbom for image and package artifacts
func SbomRun(ctx *cli.Context) error {
	opt, err := initOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	artifactType := opt.SbomOption.ArtifactType
	s, ok := artifactTypes[ArtifactType(artifactType)]
	if !ok {
		return xerrors.Errorf(`"--artifact-type" must be %q`, maps.Keys(artifactTypes))
	}

	// Scan the relevant dependencies
	opt.DisabledAnalyzers = s.disableAnalyzers
	opt.ReportOption.VulnType = []string{types.VulnTypeOS, types.VulnTypeLibrary}
	opt.ReportOption.SecurityChecks = []string{types.SecurityCheckVulnerability}

	return Run(ctx.Context, opt, s.initializer, initCache)
}
