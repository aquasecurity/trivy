package echo

import (
	"context"
	"os"
	"slices"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&echoAnalyzer{})
}

const version = 1

var requiredFiles = []string{
	"etc/echo-release",
}

type echoAnalyzer struct{}

func (a echoAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	return &analyzer.AnalysisResult{
		OS: types.OS{
			Family: types.Echo,
		},
	}, nil
}

func (a echoAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a echoAnalyzer) Type() analyzer.Type {
	return analyzer.TypeEcho
}

func (a echoAnalyzer) Version() int {
	return version
}
