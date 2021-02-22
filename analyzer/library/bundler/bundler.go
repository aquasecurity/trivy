package bundler

import (
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer/library"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/bundler"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&bundlerLibraryAnalyzer{})
}

var (
	requiredFiles = []string{"Gemfile.lock"}
)

type bundlerLibraryAnalyzer struct{}

func (a bundlerLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	res, err := library.Analyze(library.Bundler, target.FilePath, target.Content, bundler.Parse)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse Gemfile.lock: %w", err)
	}
	return res, nil
}

func (a bundlerLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a bundlerLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeBundler
}
