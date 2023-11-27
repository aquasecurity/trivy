package sbom

import (
	"context"
	"os"
	"path"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom"
	"github.com/aquasecurity/trivy/pkg/types"
)

func init() {
	analyzer.RegisterAnalyzer(&sbomAnalyzer{})
}

const version = 1

var requiredSuffixes = []string{
	".spdx",
	".spdx.json",
	".cdx",
	".cdx.json",
}

type sbomAnalyzer struct{}

func (a sbomAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	// Format auto-detection
	format, err := sbom.DetectFormat(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to detect SBOM format: %w", err)
	}

	bom, err := sbom.Decode(input.Content, format)
	if err != nil {
		return nil, xerrors.Errorf("SBOM decode error: %w", err)
	}

	// Bitnami images
	// SPDX files are located under the /opt/bitnami/<component> directory
	// and named with the pattern .spdx-<component>.spdx
	// ref: https://github.com/bitnami/vulndb#how-to-consume-this-cve-feed
	if strings.HasPrefix(input.FilePath, "opt/bitnami/") {
		handleBitnamiImages(path.Dir(input.FilePath), bom)
	}

	return &analyzer.AnalysisResult{
		PackageInfos: bom.Packages,
		Applications: bom.Applications,
	}, nil
}

func (a sbomAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	for _, suffix := range requiredSuffixes {
		if strings.HasSuffix(filePath, suffix) {
			return true
		}
	}
	return false
}

func (a sbomAnalyzer) Type() analyzer.Type {
	return analyzer.TypeSBOM
}

func (a sbomAnalyzer) Version() int {
	return version
}

func handleBitnamiImages(componentPath string, bom types.SBOM) {
	for i, app := range bom.Applications {
		if app.Type == ftypes.Bitnami {
			// Set the component dir path to the application
			bom.Applications[i].FilePath = componentPath
			// Either Application.FilePath or Application.Libraries[].FilePath should be set
			continue
		}

		for j, pkg := range app.Libraries {
			// Set the absolute path since SBOM in Bitnami images contain a relative path
			// e.g. modules/apm/elastic-apm-agent-1.36.0.jar
			//      => opt/bitnami/elasticsearch/modules/apm/elastic-apm-agent-1.36.0.jar
			// If the file path is empty, the file path will be set to the component dir path.
			bom.Applications[i].Libraries[j].FilePath = path.Join(componentPath, pkg.FilePath)
		}
	}
}
