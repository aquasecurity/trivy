package pylock

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/pylock"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePyLock, newPylockAnalyzer)
}

const version = 1

type pylockAnalyzer struct {
	lockParser language.Parser
}

func newPylockAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &pylockAnalyzer{
		lockParser: pylock.NewParser(),
	}, nil
}

func (a pylockAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, _ fs.DirEntry) bool {
		return a.matchLockFile(path) || input.FilePatterns.Match(path)
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, _ fs.DirEntry, r io.Reader) error {
		app, err := language.Parse(ctx, types.PyLock, path, r, a.lockParser)
		if err != nil {
			return xerrors.Errorf("unable to parse pylock file: %w", err)
		}
		if app == nil {
			return nil
		}

		apps = append(apps, *app)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("pylock walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a pylockAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return a.matchLockFile(filePath)
}

func (a pylockAnalyzer) matchLockFile(filePath string) bool {
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
