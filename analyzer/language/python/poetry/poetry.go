package poetry

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/language"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/python/poetry"
)

func init() {
	analyzer.RegisterAnalyzer(&poetryLibraryAnalyzer{})
}

const version = 1

var requiredFiles = []string{"poetry.lock"}

type poetryLibraryAnalyzer struct{}

func (a poetryLibraryAnalyzer) Analyze(_ context.Context, target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.Poetry, target.FilePath, target.Content, poetry.Parse)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse poetry.lock: %w", err)
	}
	return res, nil
}

func (a poetryLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a poetryLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePoetry
}

func (a poetryLibraryAnalyzer) Version() int {
	return version
}
