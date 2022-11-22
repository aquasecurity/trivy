package deps

import (
	"context"
	"os"
	"strings"

	"golang.org/x/xerrors"

	core "github.com/aquasecurity/go-dep-parser/pkg/dotnet/core_deps"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&depsLibraryAnalyzer{})
}

const (
	version       = 1
	depsExtension = ".deps.json"
)

type depsLibraryAnalyzer struct{}

func (a depsLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	parser := core.NewParser()
	res, err := language.Analyze(types.DotNetCore, input.FilePath, input.Content, parser)
	if err != nil {
		return nil, xerrors.Errorf(".Net Core dependencies analysis error: %w", err)
	}

	return res, nil
}

func (a depsLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return strings.HasSuffix(filePath, depsExtension)
}

func (a depsLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDotNetCore
}

func (a depsLibraryAnalyzer) Version() int {
	return version
}
