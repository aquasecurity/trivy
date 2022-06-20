package terraform

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

var requiredExts = []string{".tf", ".tf.json"}

type ConfigAnalyzer struct {
}

func NewConfigAnalyzer() ConfigAnalyzer {
	return ConfigAnalyzer{}
}

// Analyze returns a name of Terraform file
func (a ConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	b, err := io.ReadAll(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("read error (%s): %w", input.FilePath, err)
	}
	return &analyzer.AnalysisResult{
		Files: map[types.HandlerType][]types.File{
			// It will be passed to misconf post handler
			types.MisconfPostHandler: {
				{
					Type:    types.Terraform,
					Path:    input.FilePath,
					Content: b,
				},
			},
		},
	}, nil
}

func (a ConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredExts, filepath.Ext(filePath))
}

func (ConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeTerraform
}

func (ConfigAnalyzer) Version() int {
	return version
}
