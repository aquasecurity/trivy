package artifact

import (
	"os"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
)

type ArtifactType string

const (
	DockerArtifact  ArtifactType = "Docker"
	PackageArtifact ArtifactType = "Package"
	TarfileArtifact ArtifactType = "Tarfile"
)

var artifactTypeToScanner = map[ArtifactType]InitializeScanner{
	DockerArtifact:  dockerScanner,
	PackageArtifact: filesystemScanner,
	TarfileArtifact: archiveScanner,
}

var artifactTypeToDisabledAnalyzers = map[ArtifactType][]analyzer.Type{
	DockerArtifact:  analyzer.TypeLockfiles,
	PackageArtifact: analyzer.TypeIndividualPkgs,
	TarfileArtifact: analyzer.TypeLockfiles,
}

func extractArtifactPath(artifactPath string) (ArtifactType, string) {
	if strings.HasPrefix(artifactPath, "dir:") {
		return PackageArtifact, strings.Split(artifactPath, "dir:")[1]
	}

	if strings.HasPrefix(artifactPath, "docker:") {
		return DockerArtifact, strings.Split(artifactPath, "docker:")[1]
	}

	if exists, _ := isPathExist(artifactPath); exists {
		return PackageArtifact, artifactPath
	}

	return DockerArtifact, artifactPath
}

func isPathExist(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// SbomRun runs generates sbom for image and package artifacts
func SbomRun(ctx *cli.Context) error {
	opt, err := initOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	// Set the parsed target path
	artifactType, artifactPath := extractArtifactPath(opt.ArtifactOption.Target)
	opt.ArtifactOption.Target = artifactPath

	// Scan the relevant dependencies
	opt.DisabledAnalyzers = artifactTypeToDisabledAnalyzers[artifactType]
	opt.ReportOption.VulnType = []string{types.VulnTypeOS, types.VulnTypeLibrary}
	opt.ReportOption.SecurityChecks = []string{types.SecurityCheckVulnerability}

	return Run(ctx.Context, opt, artifactTypeToScanner[artifactType], initFSCache)
}
