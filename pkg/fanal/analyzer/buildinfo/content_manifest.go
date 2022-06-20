package buildinfo

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&contentManifestAnalyzer{})
}

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

	return &analyzer.AnalysisResult{
		BuildInfo: &types.BuildInfo{
			ContentSets: manifest.ContentSets,
		},
	}, nil
}

func (a contentManifestAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	dir, file := filepath.Split(filepath.ToSlash(filePath))
	if dir != "root/buildinfo/content_manifests/" {
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
