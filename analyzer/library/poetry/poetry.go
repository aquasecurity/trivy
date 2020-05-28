package poetry

import (
	"os"
	"path/filepath"

	"github.com/aquasecurity/fanal/analyzer/library"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/poetry"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&poetryLibraryAnalyzer{})
}

var requiredFiles = []string{"poetry.lock"}

type poetryLibraryAnalyzer struct{}

func (a poetryLibraryAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	ret, err := library.Analyze(content, poetry.Parse)
	if err != nil {
		return analyzer.AnalyzeReturn{}, xerrors.Errorf("unable to parse poetry.lock: %w", err)
	}
	return ret, nil
}

func (a poetryLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a poetryLibraryAnalyzer) Name() string {
	return library.Poetry
}
