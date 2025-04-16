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

const rockyAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&rockyOSAnalyzer{})
}

type rockyOSAnalyzer struct{}

func (a rockyOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return nil, xerrors.New("rocky: invalid rocky-release")
		}

		switch strings.ToLower(result[1]) {
		case "rocky", "rocky linux":
			return &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Rocky,
					Name:   result[2],
				},
			}, nil
		}
	}

	return nil, xerrors.Errorf("rocky: %w", fos.AnalyzeOSError)
}

func (a rockyOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(a.requiredFiles(), filePath)
}

func (a rockyOSAnalyzer) requiredFiles() []string {
	return []string{"etc/rocky-release"}
}

func (a rockyOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeRocky
}

func (a rockyOSAnalyzer) Version() int {
	return rockyAnalyzerVersion
}

// StaticPaths returns the static paths of the rocky analyzer
func (a rockyOSAnalyzer) StaticPaths() []string {
	return a.requiredFiles()
}
