package yaml

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
	analyzer.RegisterAnalyzer(&yamlConfigAnalyzer{})
}

const version = 1

var requiredExts = []string{".yaml", ".yml"}

type yamlConfigAnalyzer struct{}

func (a yamlConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	b, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to read %s: %w", input.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Files: map[types.HandlerType][]types.File{
			// it will be passed to misconfig post handler
			types.MisconfPostHandler: {
				{
					Type:    types.YAML,
					Path:    input.FilePath,
					Content: b,
				},
			},
		},
	}, nil
}

func (a yamlConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExts {
		if ext == required {
			return true
		}
	}
	return false
}

func (yamlConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeYaml
}

func (yamlConfigAnalyzer) Version() int {
	return version
}
