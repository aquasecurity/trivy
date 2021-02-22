package yarn

import (
	"os"
	"path/filepath"

	"github.com/aquasecurity/go-dep-parser/pkg/yarn"

	"github.com/aquasecurity/fanal/utils"

	"github.com/aquasecurity/fanal/analyzer/library"

	"github.com/aquasecurity/fanal/analyzer"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&yarnLibraryAnalyzer{})
}

var requiredFiles = []string{"yarn.lock"}

type yarnLibraryAnalyzer struct{}

func (a yarnLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	res, err := library.Analyze(library.Yarn, target.FilePath, target.Content, yarn.Parse)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse yarn.lock: %w", err)
	}
	return res, nil
}

func (a yarnLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a yarnLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeYarn
}
