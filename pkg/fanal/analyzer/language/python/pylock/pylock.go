package pylock

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/pylock"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&pylockAnalyzer{})
}

const version = 1

type pylockAnalyzer struct{}

func (a pylockAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(ctx, types.PyLock, input.FilePath, input.Content, pylock.NewParser())
	if err != nil {
		return nil, xerrors.Errorf("unable to parse pylock.toml: %w", err)
	}
	return res, nil
}

func (a pylockAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// Match pylock.toml or pylock.<identifier>.toml (PEP 751)
	base := filepath.Base(filePath)
	return strings.HasPrefix(base, "pylock.") && strings.HasSuffix(base, ".toml")
}

func (a pylockAnalyzer) Type() analyzer.Type {
	return analyzer.TypePyLock
}

func (a pylockAnalyzer) Version() int {
	return version
}
