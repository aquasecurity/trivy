package alpine

import (
	"bufio"
	"context"
	"golang.org/x/exp/slices"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&alpineOSAnalyzer{})
}

const version = 1

var requiredFiles = []string{"etc/alpine-release"}

type alpineOSAnalyzer struct{}

func (a alpineOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		return &analyzer.AnalysisResult{
			OS: &types.OS{Family: aos.Alpine, Name: line},
		}, nil
	}
	return nil, xerrors.Errorf("alpine: %w", aos.AnalyzeOSError)
}

func (a alpineOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a alpineOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeAlpine
}

func (a alpineOSAnalyzer) Version() int {
	return version
}
