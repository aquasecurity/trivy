package sbom

import (
	"context"
	"os"
	"path"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/sbom"
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

	// For Bitnami images
	if strings.HasPrefix(input.FilePath, "opt/bitnami/") {
		dir, file := path.Split(input.FilePath)
		bin := strings.TrimPrefix(file, ".spdx-")
		bin = strings.TrimSuffix(bin, ".spdx")
		binPath := path.Join(input.FilePath, "../bin", bin)
		for i, app := range bom.Applications {
			// Replace the SBOM path with the binary path
			bom.Applications[i].FilePath = binPath

			for j, pkg := range app.Libraries {
				if pkg.FilePath == "" {
					continue
				}
				// Set the absolute path since SBOM in Bitnami images contain a relative path
				// e.g. modules/apm/elastic-apm-agent-1.36.0.jar
				//      => opt/bitnami/elasticsearch/modules/apm/elastic-apm-agent-1.36.0.jar
				bom.Applications[i].Libraries[j].FilePath = path.Join(dir, pkg.FilePath)
			}
		}
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
