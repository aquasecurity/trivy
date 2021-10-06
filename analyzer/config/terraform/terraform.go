package terraform

import (
	"context"
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

const version = 1

const requiredExt = ".tf"

type ConfigAnalyzer struct {
}

func NewConfigAnalyzer() ConfigAnalyzer {
	return ConfigAnalyzer{}
}

// Analyze returns a name of Terraform file
func (a ConfigAnalyzer) Analyze(_ context.Context, target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	return &analyzer.AnalysisResult{
		Configs: []types.Config{
			{
				Type:     types.Terraform,
				FilePath: filepath.Join(target.Dir, target.FilePath), // tfsec requires a path from working dir
			},
		},
	}, nil
}

func (a ConfigAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Ext(filePath) == requiredExt
}

func (ConfigAnalyzer) Type() analyzer.Type {
	return analyzer.TypeTerraform
}

func (ConfigAnalyzer) Version() int {
	return version
}
