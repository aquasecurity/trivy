package bundle

import (
	"context"
	"errors"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/dotnet/bundle"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&dotnetBundleAnalyzer{})
}

const version = 1

// dotnetBundleAnalyzer analyzes .NET single-file bundles (`dotnet publish -p:PublishSingleFile=true`),
// which keep their .deps.json inside the executable instead of next to it.
type dotnetBundleAnalyzer struct{}

func (a dotnetBundleAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(ctx, types.DotNetCore, input.FilePath, input.Content, bundle.NewParser())
	if errors.Is(err, bundle.ErrUnrecognizedExe) || errors.Is(err, bundle.ErrNonBundle) {
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf(".NET single-file bundle (filepath: %s) parse error: %w", input.FilePath, err)
	}
	return res, nil
}

// Required accepts files with an executable bit and `.exe` files, which covers Windows image layers
// where the executable bit is not set.
func (a dotnetBundleAnalyzer) Required(_ string, fileInfo os.FileInfo) bool {
	return utils.IsExecutable(fileInfo)
}

func (a dotnetBundleAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDotNetBundle
}

func (a dotnetBundleAnalyzer) Version() int {
	return version
}
