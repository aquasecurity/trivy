package wolfi

import (
	"bufio"
	"context"
	"os"

	"golang.org/x/exp/slices"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	aos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&wolfiOSAnalyzer{})
}

const version = 1

var requiredFiles = []string{"etc/os-release"}

type wolfiOSAnalyzer struct{}

func (a wolfiOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()

		if line == "ID=wolfi" {
			return &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Wolfi},
			}, nil
		}
	}
	return nil, xerrors.Errorf("wolfi: %w", aos.AnalyzeOSError)
}

func (a wolfiOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a wolfiOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeWolfi
}

func (a wolfiOSAnalyzer) Version() int {
	return version
}
