package binary

import (
	"context"
	"errors"
	"os"

	"golang.org/x/xerrors"

	"github.com/deepfactor-io/go-dep-parser/pkg/golang/binary"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer/language"
	"github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&gobinaryLibraryAnalyzer{})
}

const version = 1

type gobinaryLibraryAnalyzer struct{}

func (a gobinaryLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	p := binary.NewParser()
	libs, deps, err := p.Parse(input.Content)
	if errors.Is(err, binary.ErrUnrecognizedExe) || errors.Is(err, binary.ErrNonGoBinary) {
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf("go binary (filepath: %s) parse error: %w", input.FilePath, err)
	}

	return language.ToAnalysisResult(types.GoBinary, input.FilePath, "", libs, deps), nil
}

func (a gobinaryLibraryAnalyzer) Required(_ string, fileInfo os.FileInfo) bool {
	return utils.IsExecutable(fileInfo)
}

func (a gobinaryLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGoBinary
}

func (a gobinaryLibraryAnalyzer) Version() int {
	return version
}
