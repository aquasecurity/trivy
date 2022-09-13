package terraform

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&terraformConfigAnalyzer{})
}

const version = 1

var requiredExts = []string{".tf", ".tf.json"}

type terraformConfigAnalyzer struct{}

// Analyze returns a name of Terraform file
func (a terraformConfigAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
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

func (a terraformConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredExts, filepath.Ext(filePath))
}

func (terraformConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeTerraform
}

func (terraformConfigAnalyzer) Version() int {
	return version
}
