package poetry

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/python/poetry"
	"github.com/aquasecurity/go-dep-parser/pkg/python/pyproject"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePoetry, newPoetryAnalyzer)
}

const version = 1

type poetryAnalyzer struct {
	pyprojectParser *pyproject.Parser
	lockParser      godeptypes.Parser
}

func newPoetryAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &poetryAnalyzer{
		pyprojectParser: pyproject.NewParser(),
		lockParser:      poetry.NewParser(),
	}, nil
}

func (a poetryAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == types.PoetryLock
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, d fs.DirEntry, r dio.ReadSeekerAt) error {
		// Parse poetry.lock
		app, err := a.parsePoetryLock(path, r)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Parse pyproject.toml alongside poetry.lock to identify the direct dependencies
		if err = a.mergePyProject(input.FS, filepath.Dir(path), app); err != nil {
			log.Logger.Warnf("Unable to parse %q to identify direct dependencies: %s", filepath.Join(filepath.Dir(path), types.PyProject), err)
		}
		apps = append(apps, *app)

		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("poetry walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a poetryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return fileName == types.PoetryLock || fileName == types.PyProject
}

func (a poetryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePoetry
}

func (a poetryAnalyzer) Version() int {
	return version
}

func (a poetryAnalyzer) parsePoetryLock(path string, r dio.ReadSeekerAt) (*types.Application, error) {
	return language.Parse(types.Poetry, path, r, a.lockParser)
}

func (a poetryAnalyzer) mergePyProject(fsys fs.FS, dir string, app *types.Application) error {
	// Parse pyproject.toml to identify the direct dependencies
	path := filepath.Join(dir, types.PyProject)
	p, err := a.parsePyProject(fsys, path)
	if errors.Is(err, fs.ErrNotExist) {
		// Assume all the packages are direct dependencies as it cannot identify them from poetry.lock
		log.Logger.Debugf("Poetry: %s not found", path)
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %s: %w", path, err)
	}

	for i, lib := range app.Libraries {
		// Identify the direct/transitive dependencies
		if _, ok := p[lib.Name]; !ok {
			app.Libraries[i].Indirect = true
		}
	}

	return nil
}

func (a poetryAnalyzer) parsePyProject(fsys fs.FS, path string) (map[string]interface{}, error) {
	// Parse pyproject.toml
	f, err := fsys.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	parsed, err := a.pyprojectParser.Parse(f)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}
