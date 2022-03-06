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
	DockerImageArtifact   ArtifactType = "docker"
	PackageArtifact       ArtifactType = "package"
	DockerArchiveArtifact ArtifactType = "archive"
)

var ArtifactTypes = []ArtifactType{DockerImageArtifact, PackageArtifact, DockerArchiveArtifact}

var artifactTypeToScanner = map[ArtifactType]InitializeScanner{
	DockerImageArtifact:   dockerScanner,
	PackageArtifact:       filesystemScanner,
	DockerArchiveArtifact: archiveScanner,
}

var artifactTypeToDisabledAnalyzers = map[ArtifactType][]analyzer.Type{
	DockerImageArtifact:   analyzer.TypeLockfiles,
	PackageArtifact:       analyzer.TypeIndividualPkgs,
	DockerArchiveArtifact: analyzer.TypeLockfiles,
}

func extractArtifactPath(artifactPath string) (ArtifactType, string) {
	// The user can specify the input artifact type by using the prefix "<artifact-type>:"" before the artifact path
	// e.g docker:ubuntu, package:/path/to/express
	for _, artifactType := range ArtifactTypes {
		prefix := string(artifactType) + ":"

		if strings.HasPrefix(artifactPath, prefix) {
			return artifactType, strings.Split(artifactPath, prefix)[1]
		}
	}

	fileInfo, err := os.Stat(artifactPath)
	if err != nil {
		return DockerImageArtifact, artifactPath
	}

	if fileInfo.IsDir() {
		return PackageArtifact, artifactPath
	} else {
		return DockerArchiveArtifact, artifactPath
	}
}

// SbomRun runs generates sbom for image and package artifacts
func SbomRun(ctx *cli.Context) error {
	opt, err := initOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	// Extract and set the target path
	artifactType, artifactPath := extractArtifactPath(opt.ArtifactOption.Target)
	opt.ArtifactOption.Target = artifactPath

	// Scan the relevant dependencies
	opt.DisabledAnalyzers = artifactTypeToDisabledAnalyzers[artifactType]
	opt.ReportOption.VulnType = []string{types.VulnTypeOS, types.VulnTypeLibrary}
	opt.ReportOption.SecurityChecks = []string{types.SecurityCheckVulnerability}

	return Run(ctx.Context, opt, artifactTypeToScanner[artifactType], initFSCache)
}
