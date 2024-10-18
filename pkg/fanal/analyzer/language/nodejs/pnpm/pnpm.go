package pnpm

import (
	"context"
	"github.com/aquasecurity/trivy/pkg/log"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/pnpm"
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

func (a pnpmLibraryAnalyzer) Required(filePath string, fileInfo os.FileInfo) bool {
	others := os.Getenv("NPM_PNPM")
	if size := fileInfo.Size(); size > 10485760 && others != "" { // 10MB
		log.WithPrefix("npm yarn oss").Warn("The size of the scanned file is too large. It is recommended to use `--skip-files` for this file to avoid high memory consumption.", log.Int64("size (MB)", size/1048576))
		return false
	}
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a pnpmLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePnpm
}

func (a pnpmLibraryAnalyzer) Version() int {
	return version
}
