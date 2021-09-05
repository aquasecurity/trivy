package gemspec

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/go-dep-parser/pkg/ruby/gemspec"
)

func init() {
	analyzer.RegisterAnalyzer(&gemspecLibraryAnalyzer{})
}

const version = 1

var fileRegex = regexp.MustCompile(`.*/specifications/.+\.gemspec`)

type gemspecLibraryAnalyzer struct{}

func (a gemspecLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	r := bytes.NewReader(target.Content)
	parsedLib, err := gemspec.Parse(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", target.FilePath, err)
	}

	return &analyzer.AnalysisResult{
		Applications: []types.Application{
			{
				Type:     types.GemSpec,
				FilePath: target.FilePath,
				Libraries: []types.LibraryInfo{
					{
						Library: parsedLib,
					},
				},
			},
		},
	}, nil

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
