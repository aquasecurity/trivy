package mod

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/golang/mod"
	"github.com/aquasecurity/go-dep-parser/pkg/golang/sum"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&gomodAnalyzer{})
}

const version = 2

var requiredFiles = []string{types.GoMod, types.GoSum}

type gomodAnalyzer struct{}

func (a gomodAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	var parser godeptypes.Parser
	switch filepath.Base(input.FilePath) {
	case types.GoMod:
		parser = mod.NewParser()
	case types.GoSum:
		parser = sum.NewParser()
	default:
		return nil, nil
	}

	res, err := language.Analyze(types.GoModule, input.FilePath, input.Content, parser)
	if err != nil {
		return nil, xerrors.Errorf("failed to analyze %s: %w", input.FilePath, err)
	}
	return res, nil
}

func (a gomodAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return slices.Contains(requiredFiles, fileName)
}

func (a gomodAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGoMod
}

func (a gomodAnalyzer) Version() int {
	return version
}
