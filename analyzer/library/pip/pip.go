package pip

import (
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/go-dep-parser/pkg/pip"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&pipLibraryAnalyzer{})
}

const version = 1

var requiredFile = "requirements.txt"

type pipLibraryAnalyzer struct{}

func (a pipLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	res, err := library.Analyze(types.Pip, target.FilePath, target.Content, pip.Parse)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse requirements.txt: %w", err)
	}
	return res, nil
}

func (a pipLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return fileName == requiredFile
}

func (a pipLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePip
}

func (a pipLibraryAnalyzer) Version() int {
	return version
}
