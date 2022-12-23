package mixlock

import (
	"context"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/aquasecurity/go-dep-parser/pkg/elixir/lock"

	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&mixLockAnalyzer{})
}

const (
	version        = 1
	fileNameSuffix = "mix.lock"
)

// mixLockAnalyzer analyzes 'mix.lock'
type mixLockAnalyzer struct{}

func (a mixLockAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	p := lock.NewParser()
	res, err := language.Analyze(types.ElixirLock, input.FilePath, input.Content, p)
	if err != nil {
		return nil, xerrors.Errorf("%s parse error: %w", input.FilePath, err)
	}
	return res, nil
}

func (a mixLockAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return strings.HasSuffix(filePath, fileNameSuffix)
}

func (a mixLockAnalyzer) Type() analyzer.Type {
	return analyzer.TypeElixirLock
}

func (a mixLockAnalyzer) Version() int {
	return version
}
