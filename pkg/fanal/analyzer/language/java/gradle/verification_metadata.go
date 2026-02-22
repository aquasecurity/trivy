package gradle

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/gradle/verification_metadata"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type gradleVerificationMetadataAnalyzer struct {
	parser language.Parser
}

func init() {
	analyzer.RegisterAnalyzer(&gradleVerificationMetadataAnalyzer{
		parser: verification_metadata.NewParser(),
	})
}

func (a gradleVerificationMetadataAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(ctx, types.Gradle, input.FilePath, input.Content, a.parser)

	if err != nil {
		return nil, xerrors.Errorf("%s parse error: %w", input.FilePath, err)
	}

	return res, nil
}

func (a gradleVerificationMetadataAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return types.GradleVerificationMetadata == filepath.Base(filePath)
}

func (a gradleVerificationMetadataAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGradleVerificationMetadata
}

func (a gradleVerificationMetadataAnalyzer) Version() int {
	return 1
}
