package pnpm

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/pnpm"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&pnpmLibraryAnalyzer{})
}

const version = 1

var requiredFiles = []string{types.PnpmLock}

type pnpmLibraryAnalyzer struct{}

func (a pnpmLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.Pnpm, input.FilePath, input.Content, pnpm.NewParser())
	if err != nil {
		return nil, xerrors.Errorf("unable to parse %s: %w", input.FilePath, err)
	}
	return res, nil
}

func (a pnpmLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a pnpmLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePnpm
}

func (a pnpmLibraryAnalyzer) Version() int {
	return version
}
