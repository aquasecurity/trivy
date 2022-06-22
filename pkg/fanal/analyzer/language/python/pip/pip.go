package pip

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/python/pip"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&pipLibraryAnalyzer{})
}

const version = 1

type pipLibraryAnalyzer struct{}

func (a pipLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.Pip, input.FilePath, input.Content, pip.NewParser())
	if err != nil {
		return nil, xerrors.Errorf("unable to parse requirements.txt: %w", err)
	}
	return res, nil
}

func (a pipLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return fileName == types.PipRequirements
}

func (a pipLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePip
}

func (a pipLibraryAnalyzer) Version() int {
	return version
}
