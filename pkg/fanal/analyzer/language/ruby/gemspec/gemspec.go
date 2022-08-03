package gemspec

import (
	"context"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/xerrors"

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
	p := gemspec.NewParser()
	libs, deps, err := p.Parse(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("%s parse error: %w", input.FilePath, err)
	}

	return language.ToAnalysisResult(types.GemSpec, input.FilePath, input.FilePath, libs, deps), nil
}

func (a gemspecLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return fileRegex.MatchString(filepath.ToSlash(filePath))
}

func (a gemspecLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGemSpec
}

func (a gemspecLibraryAnalyzer) Version() int {
	return version
}
