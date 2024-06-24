package packagesprops

import (
	"context"
	"os"
	"strings"

	"golang.org/x/xerrors"

	props "github.com/aquasecurity/trivy/pkg/dependency/parser/nuget/packagesprops"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&packagesPropsAnalyzer{})
}

const (
	version             = 1
	packagesPropsSuffix = "packages.props" // https://github.com/dotnet/roslyn-tools/blob/b4c5220f5dfc4278847b6d38eff91cc1188f8066/src/RoslynInsertionTool/RoslynInsertionTool/CoreXT.cs#L39-L40
)

type packagesPropsAnalyzer struct{}

func (a packagesPropsAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	parser := props.NewParser()
	res, err := language.Analyze(types.PackagesProps, input.FilePath, input.Content, parser)
	if err != nil {
		return nil, xerrors.Errorf("*Packages.props dependencies analysis error: %w", err)
	}

	return res, nil
}

func (a packagesPropsAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// There is no information about this in the documentation,
	// but NuGet works correctly with lowercase filenames
	return strings.HasSuffix(strings.ToLower(filePath), packagesPropsSuffix)
}

func (a packagesPropsAnalyzer) Type() analyzer.Type {
	return analyzer.TypePackagesProps
}

func (a packagesPropsAnalyzer) Version() int {
	return version
}
