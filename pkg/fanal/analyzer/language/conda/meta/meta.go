package meta

import (
	"context"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/conda/meta"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&metaAnalyzer{})
}

const version = 1

var fileRegex = regexp.MustCompile(`.*/envs/.+/conda-meta/.+-.+-.+\.json`)

type metaAnalyzer struct{}

func (a metaAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	p := meta.NewParser()
	libs, deps, err := p.Parse(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("%s parse error: %w", input.FilePath, err)
	}

	return language.ToAnalysisResult(types.CondaPkg, input.FilePath, input.FilePath, libs, deps), nil
}
func (a metaAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return fileRegex.MatchString(filepath.ToSlash(filePath))
}

func (a metaAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCondaPkg
}

func (a metaAnalyzer) Version() int {
	return version
}
