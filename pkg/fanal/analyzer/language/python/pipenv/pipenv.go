package pipenv

import (
	"context"
	"github.com/aquasecurity/trivy/pkg/log"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/pipenv"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
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

func (a pipenvLibraryAnalyzer) Required(filePath string, fileInfo os.FileInfo) bool {
	others := os.Getenv("PYTHON")
	if size := fileInfo.Size(); size > 10485760 && others != "" { // 10MB
		log.WithPrefix("npm yarn oss").Warn("The size of the scanned file is too large. It is recommended to use `--skip-files` for this file to avoid high memory consumption.", log.Int64("size (MB)", size/1048576))
		return false
	}
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a pipenvLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePipenv
}

func (a pipenvLibraryAnalyzer) Version() int {
	return version
}
