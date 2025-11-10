package debian

import (
	"bufio"
	"context"
	"os"
	"slices"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&debianOSAnalyzer{})
}

const version = 1

var requiredFiles = []string{"etc/debian_version"}

type debianOSAnalyzer struct{}

func (a debianOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		return &analyzer.AnalysisResult{
			OS: types.OS{
				Family: types.Debian,
				Name:   line,
			},
		}, nil
	}
	return nil, xerrors.Errorf("debian: %w", fos.AnalyzeOSError)
}

func (a debianOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a debianOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDebian
}

func (a debianOSAnalyzer) Version() int {
	return version
}

// StaticPaths returns the static paths of the debian analyzer
func (a debianOSAnalyzer) StaticPaths() []string {
	return requiredFiles
}
