package artifact

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/types"
)

type ArtifactType string

const (
	ContainerImageArtifact ArtifactType = "image"
	PackageArtifact        ArtifactType = "fs"
	DockerArchiveArtifact  ArtifactType = "archive"
)

var ArtifactTypes = []ArtifactType{ContainerImageArtifact, PackageArtifact, DockerArchiveArtifact}

var artifactTypeToScanner = map[ArtifactType]InitializeScanner{
	ContainerImageArtifact: dockerScanner,
	PackageArtifact:        filesystemScanner,
	DockerArchiveArtifact:  archiveScanner,
}

var artifactTypeToDisabledAnalyzers = map[ArtifactType][]analyzer.Type{
	ContainerImageArtifact: analyzer.TypeLockfiles,
	PackageArtifact:        analyzer.TypeIndividualPkgs,
	DockerArchiveArtifact:  analyzer.TypeLockfiles,
}

// SbomRun runs generates sbom for image and package artifacts
func SbomRun(ctx *cli.Context) error {
	opt, err := initOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	artifactType := opt.ArtifactOption.Type

	if err != nil {
		return err
	}

	// Scan the relevant dependencies
	opt.DisabledAnalyzers = artifactTypeToDisabledAnalyzers[ArtifactType(artifactType)]
	opt.ReportOption.VulnType = []string{types.VulnTypeOS, types.VulnTypeLibrary}
	opt.ReportOption.SecurityChecks = []string{types.SecurityCheckVulnerability}

	return Run(ctx.Context, opt, artifactTypeToScanner[ArtifactType(artifactType)], initFSCache)
}
