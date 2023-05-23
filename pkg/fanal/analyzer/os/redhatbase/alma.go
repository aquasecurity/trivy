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

const almaAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&almaOSAnalyzer{})
}

type almaOSAnalyzer struct{}

func (a almaOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return nil, xerrors.New("alma: invalid almalinux-release")
		}

		switch strings.ToLower(result[1]) {
		case "alma", "almalinux", "alma linux":
			return &analyzer.AnalysisResult{
				OS: types.OS{Family: aos.Alma, Name: result[2]},
			}, nil
		}
	}

	return nil, xerrors.Errorf("alma: %w", aos.AnalyzeOSError)
}

func (a almaOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a almaOSAnalyzer) requiredFiles() []string {
	return []string{"etc/almalinux-release"}
}

func (a almaOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeAlma
}

func (a almaOSAnalyzer) Version() int {
	return almaAnalyzerVersion
}
