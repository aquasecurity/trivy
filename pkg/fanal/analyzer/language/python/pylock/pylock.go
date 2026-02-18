package pylock

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/pylock"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/pyproject"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePyLock, newPylockAnalyzer)
}

const version = 1

type pylockAnalyzer struct {
	logger          *log.Logger
	lockParser      language.Parser
	pyprojectParser *pyproject.Parser
}

func newPylockAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &pylockAnalyzer{
		logger:          log.WithPrefix("pylock"),
		lockParser:      pylock.NewParser(),
		pyprojectParser: pyproject.NewParser(),
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

		// Parse pyproject.toml alongside pylock.toml to identify direct dependencies
		if err = a.mergePyProject(input.FS, filepath.Dir(path), app); err != nil {
			a.logger.Warn("Unable to parse pyproject.toml to identify direct dependencies",
				log.FilePath(filepath.Join(filepath.Dir(path), types.PyProject)), log.Err(err))
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
	fileName := filepath.Base(filePath)
	return a.matchLockFile(filePath) || fileName == types.PyProject
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

func (a pylockAnalyzer) mergePyProject(fsys fs.FS, dir string, app *types.Application) error {
	path := filepath.Join(dir, types.PyProject)
	p, err := a.parsePyProject(fsys, path)
	if errors.Is(err, fs.ErrNotExist) {
		a.logger.Debug("pyproject.toml not found", log.FilePath(path))
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %s: %w", path, err)
	}

	directDeps := p.MainDeps()

	// Mark direct/indirect dependencies
	for i, pkg := range app.Packages {
		app.Packages[i].Relationship = types.RelationshipIndirect
		if directDeps.Contains(pkg.Name) {
			app.Packages[i].Relationship = types.RelationshipDirect
		}
	}

	return nil
}

func (a pylockAnalyzer) parsePyProject(fsys fs.FS, path string) (pyproject.PyProject, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return pyproject.PyProject{}, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	p, err := a.pyprojectParser.Parse(f)
	if err != nil {
		return pyproject.PyProject{}, xerrors.Errorf("parse error: %w", err)
	}

	return p, nil
}
