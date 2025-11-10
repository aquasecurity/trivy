package ubuntu

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

func init() {
	analyzer.RegisterAnalyzer(&ubuntuOSAnalyzer{})
}

const (
	version            = 1
	ubuntuConfFilePath = "etc/lsb-release"
)

var requiredFiles = []string{
	ubuntuConfFilePath,
}

type ubuntuOSAnalyzer struct{}

func (a ubuntuOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	isUbuntu := false
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "DISTRIB_ID=Ubuntu" {
			isUbuntu = true
			continue
		}

		if isUbuntu && strings.HasPrefix(line, "DISTRIB_RELEASE=") {
			return &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Ubuntu,
					Name:   strings.TrimSpace(line[16:]),
				},
			}, nil
		}
	}
	return nil, xerrors.Errorf("ubuntu: %w", fos.AnalyzeOSError)
}

func (a ubuntuOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a ubuntuOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeUbuntu
}

func (a ubuntuOSAnalyzer) Version() int {
	return version
}

// StaticPaths returns the static paths of the ubuntu analyzer
func (a ubuntuOSAnalyzer) StaticPaths() []string {
	return requiredFiles
}
