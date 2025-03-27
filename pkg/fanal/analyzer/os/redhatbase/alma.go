package redhatbase

import (
	"bufio"
	"context"
	"os"
	"slices"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
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
				OS: types.OS{
					Family: types.Alma,
					Name:   result[2],
				},
			}, nil
		}
	}

	return nil, xerrors.Errorf("alma: %w", fos.AnalyzeOSError)
}

func (a almaOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(a.requiredFiles(), filePath)
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

// StaticPaths returns the static paths of the alma analyzer
func (a almaOSAnalyzer) StaticPaths() []string {
	return a.requiredFiles()
}
