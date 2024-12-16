package poetry

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/poetry"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/pyproject"
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
	logger          *log.Logger
	pyprojectParser *pyproject.Parser
	lockParser      language.Parser
}

func newPoetryAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &poetryAnalyzer{
		logger:          log.WithPrefix("poetry"),
		pyprojectParser: pyproject.NewParser(),
		lockParser:      poetry.NewParser(),
	}, nil
}

func (a poetryAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == types.PoetryLock
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, d fs.DirEntry, r io.Reader) error {
		// Parse poetry.lock
		app, err := a.parsePoetryLock(path, r)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Parse pyproject.toml alongside poetry.lock to identify the direct dependencies
		if err = a.mergePyProject(input.FS, filepath.Dir(path), app); err != nil {
			a.logger.Warn("Unable to parse pyproject.toml to identify direct dependencies",
				log.FilePath(filepath.Join(filepath.Dir(path), types.PyProject)), log.Err(err))
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

func (a poetryAnalyzer) parsePoetryLock(path string, r io.Reader) (*types.Application, error) {
	return language.Parse(types.Poetry, path, r, a.lockParser)
}

func (a poetryAnalyzer) mergePyProject(fsys fs.FS, dir string, app *types.Application) error {
	// Parse pyproject.toml to identify the direct dependencies
	path := filepath.Join(dir, types.PyProject)
	project, err := a.parsePyProject(fsys, path)
	if errors.Is(err, fs.ErrNotExist) {
		// Assume all the packages are direct dependencies as it cannot identify them from poetry.lock
		a.logger.Debug("pyproject.toml not found", log.FilePath(path))
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %s: %w", path, err)
	}

	// Identify the direct/transitive dependencies
	for i, pkg := range app.Packages {
		if _, ok := project.Tool.Poetry.Dependencies[pkg.Name]; ok {
			app.Packages[i].Relationship = types.RelationshipDirect
		} else {
			app.Packages[i].Indirect = true
			app.Packages[i].Relationship = types.RelationshipIndirect
		}
	}

	prodDeps := getProdDeps(project, app)

	app.Packages = lo.Filter(app.Packages, func(pkg types.Package, _ int) bool {
		_, ok := prodDeps[packageNameFromID(pkg.ID)]
		return ok
	})

	return nil
}

func getProdDeps(project pyproject.PyProject, app *types.Application) map[string]struct{} {
	packages := lo.SliceToMap(app.Packages, func(pkg types.Package) (string, types.Package) {
		return packageNameFromID(pkg.ID), pkg
	})

	visited := make(map[string]struct{})
	for depName := range project.Tool.Poetry.Dependencies {
		walkPackageDeps(depName, packages, visited)
	}

	for group, groupDeps := range project.Tool.Poetry.Groups {
		if group == "dev" {
			continue
		}
		for depName := range groupDeps.Dependencies {
			walkPackageDeps(depName, packages, visited)
		}
	}
	return visited
}

func walkPackageDeps(packageName string, packages map[string]types.Package, visited map[string]struct{}) {
	if _, ok := visited[packageName]; ok {
		return
	}
	visited[packageName] = struct{}{}
	pkg, exists := packages[packageName]
	if !exists {
		return
	}

	for _, dep := range pkg.DependsOn {
		walkPackageDeps(packageNameFromID(dep), packages, visited)
	}
}

func packageNameFromID(id string) string {
	return strings.Split(id, "@")[0]
}

func (a poetryAnalyzer) parsePyProject(fsys fs.FS, path string) (pyproject.PyProject, error) {
	// Parse pyproject.toml
	f, err := fsys.Open(path)
	if err != nil {
		return pyproject.PyProject{}, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	project, err := a.pyprojectParser.Parse(f)
	if err != nil {
		return pyproject.PyProject{}, err
	}

	return project, nil
}
