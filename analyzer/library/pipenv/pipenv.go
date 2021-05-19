package pipenv

import (
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/pipenv"
)

func init() {
	analyzer.RegisterAnalyzer(&pipenvLibraryAnalyzer{})
}

const version = 1

var requiredFiles = []string{"Pipfile.lock"}

type pipenvLibraryAnalyzer struct{}

func (a pipenvLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	res, err := library.Analyze(types.Pipenv, target.FilePath, target.Content, pipenv.Parse)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse Pipfile.lock: %w", err)
	}
	return res, nil
}

func (a pipenvLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a pipenvLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePipenv
}

func (a pipenvLibraryAnalyzer) Version() int {
	return version
}
