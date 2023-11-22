package packagesprops

import (
	"context"
	"os"
	"strings"

	"golang.org/x/xerrors"

	props "github.com/aquasecurity/go-dep-parser/pkg/nuget/packagesprops"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&packagesPropsAnalyzer{})
}

const (
	version             = 1
	packagesPropsSuffix = "packages.props"
)

type packagesPropsAnalyzer struct{}

func (a packagesPropsAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	parser := props.NewParser()
	res, err := language.Analyze(types.PackagesProps, input.FilePath, input.Content, parser)
	if err != nil {
		return nil, xerrors.Errorf("*packages.props dependencies analysis error: %w", err)
	}

	return res, nil
}

func (a packagesPropsAnalyzer) Required(filePath string, _ os.FileInfo) bool {

	return strings.HasSuffix(strings.ToLower(filePath), packagesPropsSuffix)
}

func (a packagesPropsAnalyzer) Type() analyzer.Type {
	return analyzer.TypePackagesProps
}

func (a packagesPropsAnalyzer) Version() int {
	return version
}
