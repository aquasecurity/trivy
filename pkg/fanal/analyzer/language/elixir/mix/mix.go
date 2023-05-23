package mix

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/hex/mix"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&mixLockAnalyzer{})
}

const (
	version = 1
)

// mixLockAnalyzer analyzes 'mix.lock'
type mixLockAnalyzer struct{}

func (a mixLockAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	p := mix.NewParser()
	res, err := language.Analyze(types.Hex, input.FilePath, input.Content, p)
	if err != nil {
		return nil, xerrors.Errorf("%s parse error: %w", input.FilePath, err)
	}
	return res, nil
}

func (a mixLockAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// Lock file name can be anything.
	// cf. https://hexdocs.pm/mix/Mix.Project.html#module-configuration
	// By default, we only check the default file name - `mix.lock`.
	return filepath.Base(filePath) == types.MixLock
}

func (a mixLockAnalyzer) Type() analyzer.Type {
	return analyzer.TypeMixLock
}

func (a mixLockAnalyzer) Version() int {
	return version
}
