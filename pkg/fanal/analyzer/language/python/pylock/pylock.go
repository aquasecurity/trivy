package pylock

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	pylockparser "github.com/aquasecurity/trivy/pkg/dependency/parser/python/pylock"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePyLock, NewPyLockAnalyzer)
}

const version = 1

type pyLockAnalyzer struct {
	logger     *log.Logger
	lockParser language.Parser
}

func NewPyLockAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &pyLockAnalyzer{
		logger:     log.WithPrefix("pylock"),
		lockParser: pylockparser.NewParser(),
	}, nil
}

func (a *pyLockAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application
	required := func(_ string, _ fs.DirEntry) bool {
		return true
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, _ fs.DirEntry, r io.Reader) error {
		app, err := language.Parse(ctx, types.PyLock, path, r, a.lockParser)
		if err != nil {
			a.logger.Warn("Failed to parse pylock.toml", log.Err(err))
			return nil
		} else if app == nil {
			return nil
		}

		apps = append(apps, *app)

		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a *pyLockAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == types.PyLockFile
}

func (a *pyLockAnalyzer) Type() analyzer.Type {
	return analyzer.TypePyLock
}

func (a *pyLockAnalyzer) Version() int {
	return version
}
