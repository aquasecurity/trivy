package binary

import (
	"context"
	"errors"
	"github.com/aquasecurity/trivy/pkg/log"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/golang/binary"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&gobinaryLibraryAnalyzer{})
}

const version = 1

type gobinaryLibraryAnalyzer struct{}

func (a gobinaryLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	p := binary.NewParser()
	res, err := language.Analyze(types.GoBinary, input.FilePath, input.Content, p)
	if errors.Is(err, binary.ErrUnrecognizedExe) || errors.Is(err, binary.ErrNonGoBinary) {
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf("go binary (filepath: %s) parse error: %w", input.FilePath, err)
	}

	return res, nil
}

func (a gobinaryLibraryAnalyzer) Required(_ string, fileInfo os.FileInfo) bool {
	others := os.Getenv("GOLANG_BINARY")
	if size := fileInfo.Size(); size > 10485760 && others != "" { // 10MB
		log.WithPrefix("golang oss binary").Warn("The size of the scanned file is too large. It is recommended to use `--skip-files` for this file to avoid high memory consumption.", log.Int64("size (MB)", size/1048576))
		return false
	}
	return utils.IsExecutable(fileInfo)
}

func (a gobinaryLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGoBinary
}

func (a gobinaryLibraryAnalyzer) Version() int {
	return version
}
