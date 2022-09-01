package json

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&jsonConfigAnalyzer{})
}

const version = 1

var (
	requiredExt   = ".json"
	excludedFiles = []string{types.NpmPkgLock, types.NuGetPkgsLock, types.NuGetPkgsConfig}
)

type jsonConfigAnalyzer struct{}

func (a jsonConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	b, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to read %s: %w", input.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Files: map[types.HandlerType][]types.File{
			// It will be passed to misconfig post handler
			types.MisconfPostHandler: {
				{
					Type:    types.JSON,
					Path:    input.FilePath,
					Content: b,
				},
			},
		},
	}, nil
}

func (a jsonConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	filename := filepath.Base(filePath)
	for _, excludedFile := range excludedFiles {
		if filename == excludedFile {
			return false
		}
	}

	return filepath.Ext(filePath) == requiredExt
}

func (jsonConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJSON
}

func (jsonConfigAnalyzer) Version() int {
	return version
}
