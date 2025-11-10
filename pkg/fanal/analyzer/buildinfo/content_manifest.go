package buildinfo

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

func init() {
	analyzer.RegisterAnalyzer(&contentManifestAnalyzer{})
}

var contentSetsDirs = set.New[string](
	"root/buildinfo/content_manifests/",
	"usr/share/buildinfo/", // for RHCOS
)

const contentManifestAnalyzerVersion = 1

type contentManifest struct {
	ContentSets []string `json:"content_sets"`
}

// For Red Hat products
type contentManifestAnalyzer struct{}

func (a contentManifestAnalyzer) Analyze(_ context.Context, target analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	var manifest contentManifest
	if err := json.NewDecoder(target.Content).Decode(&manifest); err != nil {
		return nil, xerrors.Errorf("invalid content manifest: %w", err)
	}

	if len(manifest.ContentSets) == 0 {
		return nil, nil
	}

	return &analyzer.AnalysisResult{
		BuildInfo: &types.BuildInfo{
			ContentSets: manifest.ContentSets,
		},
	}, nil
}

func (a contentManifestAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	dir, file := filepath.Split(filepath.ToSlash(filePath))
	if !contentSetsDirs.Contains(dir) {
		return false
	}
	return filepath.Ext(file) == ".json"
}

func (a contentManifestAnalyzer) Type() analyzer.Type {
	return analyzer.TypeRedHatContentManifestType
}

func (a contentManifestAnalyzer) Version() int {
	return contentManifestAnalyzerVersion
}

func (a contentManifestAnalyzer) StaticPaths() []string {
	return contentSetsDirs.Items()
}
