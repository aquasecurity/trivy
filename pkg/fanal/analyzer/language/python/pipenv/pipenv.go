package pipenv

import (
	"context"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/pipenv"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&pipenvLibraryAnalyzer{})
}

const version = 1

var requiredFiles = []string{types.PipfileLock}

type pipenvLibraryAnalyzer struct{}

func (a pipenvLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.Pipenv, input.FilePath, input.Content, pipenv.NewParser())
	if err != nil {
		return nil, xerrors.Errorf("unable to parse Pipfile.lock: %w", err)
	}
	return res, nil
}

func (a pipenvLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return slices.Contains(requiredFiles, fileName)
}

func (a pipenvLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePipenv
}

func (a pipenvLibraryAnalyzer) Version() int {
	return version
}
