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
	ContainerImageArtifact ArtifactType = "image"
	PackageArtifact        ArtifactType = "dir"
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

func analyzeArtifactPath(artifactPath string) (ArtifactType, string) {
	// The user can specify the input artifact type by using the "<artifact-type>:" prefix before the artifact path
	// e.g image:ubuntu, dir:/path/to/express
	for _, artifactType := range ArtifactTypes {
		prefix := string(artifactType) + ":"

		if strings.HasPrefix(artifactPath, prefix) {
			return artifactType, strings.Split(artifactPath, prefix)[1]
		}
	}

	return detectArtifactType(artifactPath), artifactPath

}

// Detect the artifact type by checking if it is a file, directory or does not exist
func detectArtifactType(artifactPath string) ArtifactType {
	fileInfo, err := os.Stat(artifactPath)
	if err != nil {
		return ContainerImageArtifact
	}

	if fileInfo.IsDir() {
		return PackageArtifact
	}
	return DockerArchiveArtifact
}

// SbomRun runs generates sbom for image and package artifacts
func SbomRun(ctx *cli.Context) error {
	opt, err := initOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	// Extract and set the target path
	artifactType, artifactPath := analyzeArtifactPath(opt.ArtifactOption.Target)
	opt.ArtifactOption.Target = artifactPath

	// Scan the relevant dependencies
	opt.DisabledAnalyzers = artifactTypeToDisabledAnalyzers[artifactType]
	opt.ReportOption.VulnType = []string{types.VulnTypeOS, types.VulnTypeLibrary}
	opt.ReportOption.SecurityChecks = []string{types.SecurityCheckVulnerability}

	return Run(ctx.Context, opt, artifactTypeToScanner[artifactType], initFSCache)
}
