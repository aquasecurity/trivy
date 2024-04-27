package environment

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/conda/environment"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&environmentAnalyzer{})
}

const version = 1

type environmentAnalyzer struct{}

func (a environmentAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.CondaEnv, input.FilePath, input.Content, environment.NewParser())
	if err != nil {
		return nil, xerrors.Errorf("unable to parse environment.yaml: %w", err)
	}
	return res, nil
}
func (a environmentAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == types.CondaEnvYml || filepath.Base(filePath) == types.CondaEnvYaml
}

func (a environmentAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCondaEnv
}

func (a environmentAnalyzer) Version() int {
	return version
}
