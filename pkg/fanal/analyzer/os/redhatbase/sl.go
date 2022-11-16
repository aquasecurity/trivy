package redhatbase

import (
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"

	"golang.org/x/xerrors"

	aos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

const slAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&slOSAnalyzer{})
}

type slOSAnalyzer struct{}

func (a slOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return nil, xerrors.New("sl: invalid sl-release")
		}

		switch strings.ToLower(result[1]) {
		case "sl", "scientific", "scientific linux":
			return &analyzer.AnalysisResult{
				OS: &types.OS{Family: aos.Alma, Name: result[2]},
			}, nil
		}
	}

	return nil, xerrors.Errorf("sl: %w", aos.AnalyzeOSError)
}

func (a slOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a slOSAnalyzer) requiredFiles() []string {
	return []string{"etc/sl-release"}
}

func (a slOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeAlma
}

func (a slOSAnalyzer) Version() int {
	return slAnalyzerVersion
}
