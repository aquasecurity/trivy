package pkgjl

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	julia "github.com/aquasecurity/trivy/pkg/dependency/parser/julia/manifest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeJulia, newJuliaAnalyzer)
}

const version = 1

var requiredFiles = []string{
	types.JuliaManifest,
	types.JuliaProject,
}

type juliaAnalyzer struct {
	lockParser language.Parser
	logger     *log.Logger
}

type Project struct {
	Dependencies map[string]string `toml:"deps"`
	Extras       map[string]string `toml:"extras"`
}

func newJuliaAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &juliaAnalyzer{
		lockParser: julia.NewParser(),
		logger:     log.WithPrefix("julia"),
	}, nil
}

func (a juliaAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == types.JuliaManifest
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, d fs.DirEntry, r io.Reader) error {
		// Parse Manifest.toml
		app, err := a.parseJuliaManifest(path, r)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Parse Project.toml alongside Manifest.toml to identify the direct dependencies. This mutates `app`.
		if err = a.analyzeDependencies(input.FS, filepath.Dir(path), app); err != nil {
			a.logger.Warn("Unable to parse file to analyze dependencies",
				log.FilePath(filepath.Join(filepath.Dir(path), types.JuliaProject)), log.Err(err))
		}

		sort.Sort(app.Packages)
		apps = append(apps, *app)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("julia walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a juliaAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return slices.Contains(requiredFiles, fileName)
}

func (a juliaAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJulia
}

func (a juliaAnalyzer) Version() int {
	return version
}

func (a juliaAnalyzer) parseJuliaManifest(path string, r io.Reader) (*types.Application, error) {
	return language.Parse(types.Julia, path, r, a.lockParser)
}

func (a juliaAnalyzer) analyzeDependencies(fsys fs.FS, dir string, app *types.Application) error {
	deps, devDeps, err := a.getProjectDeps(fsys, dir)
	if err != nil {
		return err
	}

	pkgs := walkDependencies(deps, app.Packages, false)
	devPkgs := walkDependencies(devDeps, app.Packages, true)
	app.Packages = append(pkgs, devPkgs...)
	return nil
}

// getProjectDeps parses project.toml and returns root and dev dependencies.
func (a juliaAnalyzer) getProjectDeps(fsys fs.FS, dir string) (map[string]string, map[string]string, error) {
	projectPath := filepath.Join(dir, types.JuliaProject)
	project, err := parseJuliaProject(fsys, projectPath)
	if errors.Is(err, fs.ErrNotExist) {
		a.logger.Debug("Julia project not found", log.String("PROJECT_PATH", projectPath))
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, xerrors.Errorf("unable to parse %s: %w", projectPath, err)
	}
	return project.Dependencies, project.Extras, nil
}

// Parses Project.toml
func parseJuliaProject(fsys fs.FS, path string) (Project, error) {
	proj := Project{}
	f, err := fsys.Open(path)
	if err != nil {
		return proj, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err = toml.NewDecoder(f).Decode(&proj); err != nil {
		return proj, xerrors.Errorf("decode error: %w", err)
	}
	return proj, nil
}

// Marks the given direct dependencies as direct, then marks those packages' dependencies as indirect.
// Marks all encountered packages' Dev flag according to `dev`.
// Modifies the packages in `allPackages`.
func walkDependencies(directDeps map[string]string, allPackages types.Packages, dev bool) []types.Package {
	pkgsByID := lo.SliceToMap(allPackages, func(pkg types.Package) (string, types.Package) {
		return pkg.ID, pkg
	})

	// Identify direct dependencies
	// Everything in `directDeps` is assumed to be direct
	visited := make(map[string]types.Package)
	for _, uuid := range directDeps {
		if pkg, ok := pkgsByID[uuid]; ok {
			pkg.Indirect = false
			pkg.Dev = dev
			visited[pkg.ID] = pkg
		}
	}

	// Identify indirect dependencies
	for _, pkg := range visited {
		walkIndirectDependencies(pkg, pkgsByID, visited)
	}

	return lo.Values(visited)
}

// Marks all indirect dependencies as indirect. Starts from `rootPkg`. Visited deps are added to `visited`.
func walkIndirectDependencies(rootPkg types.Package, allPkgIDs, visited map[string]types.Package) {
	for _, pkgID := range rootPkg.DependsOn {
		if _, ok := visited[pkgID]; ok {
			continue
		}

		dep, ok := allPkgIDs[pkgID]
		if !ok {
			continue
		}

		dep.Indirect = true
		dep.Dev = rootPkg.Dev
		visited[dep.ID] = dep
		walkIndirectDependencies(dep, allPkgIDs, visited)
	}
}
