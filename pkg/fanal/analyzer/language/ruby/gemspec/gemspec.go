package gemspec

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/ruby/gemspec"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&gemspecLibraryAnalyzer{})
}

const version = 1

var fileRegex = regexp.MustCompile(`.*/specifications/.+\.gemspec`)

type gemspecLibraryAnalyzer struct{}

func (a gemspecLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	return language.AnalyzePackage(types.GemSpec, input.FilePath, input.Content,
		gemspec.NewParser(), input.Options.FileChecksum)
}

func (a gemspecLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// Bitnami images have SBOMs inside, so there is no need to analyze Ruby packages.
	if strings.HasPrefix(filePath, "opt/bitnami") {
		return false
	}
	return fileRegex.MatchString(filepath.ToSlash(filePath))
}

func (a gemspecLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGemSpec
}

func (a gemspecLibraryAnalyzer) Version() int {
	return version
}
