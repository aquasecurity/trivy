package julia

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
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
	lockParser godeptypes.Parser
	comparer   compare.GenericComparer
}

type Project struct {
	Name         string
	UUID         string
	Keywords     []string
	License      string
	Description  string `toml:"desc"`
	Version      string
	Authors      []string
	Dependencies map[string]string `toml:"deps"`
	Compat       map[string]string
	Extras       map[string]string
	Targets      map[string][]string
}

func newJuliaAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &juliaAnalyzer{
		lockParser: NewParser(),
		comparer:   compare.GenericComparer{},
	}, nil
}

func (a juliaAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == types.JuliaManifest
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, d fs.DirEntry, r dio.ReadSeekerAt) error {
		// Parse Manifest.toml
		app, err := a.parseJuliaManifest(path, r)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Parse Project.toml alongside Manifest.toml to identify the direct dependencies. This mutates `app`.
		if err = a.removeExtraDependencies(input.FS, filepath.Dir(path), app); err != nil {
			log.Logger.Warnf("Unable to parse %q to identify direct dependencies: %s", filepath.Join(filepath.Dir(path), types.JuliaProject), err)
		}

		sort.Sort(types.Packages(app.Libraries))
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

func (a juliaAnalyzer) parseJuliaManifest(path string, r dio.ReadSeekerAt) (*types.Application, error) {
	return language.Parse(types.Julia, path, r, a.lockParser)
}

// Removes dependencies not specified as direct dependencies in the Project.toml file.
// This is not strictly necessary, but given that test dependencies are in flux right now, this is future-proofing.
// https://pkgdocs.julialang.org/v1/creating-packages/#target-based-test-specific-dependencies
func (a juliaAnalyzer) removeExtraDependencies(fsys fs.FS, dir string, app *types.Application) error {
	projectPath := filepath.Join(dir, types.JuliaProject)
	project, err := parseJuliaProject(fsys, projectPath)
	if errors.Is(err, fs.ErrNotExist) {
		log.Logger.Debugf("Julia: %s not found", projectPath)
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %s: %w", projectPath, err)
	}

	// Project.toml file can contain same libraries with different versions.
	// Save versions separately for version comparison by comparator
	pkgIDs := lo.SliceToMap(app.Libraries, func(pkg types.Package) (string, types.Package) {
		return pkg.ID, pkg
	})

	// Identify direct dependencies
	visited := map[string]types.Package{}
	for _, uuid := range project.Dependencies {
		// uuid is a direct dep since it's in the Project file. Search through Libraries to mark the matching one as a direct dep.
		for _, pkg := range app.Libraries {
			// Check using prefix because pkg.ID is uuid@version
			if !strings.HasPrefix(pkg.ID, uuid) {
				continue
			}

			// Mark as a direct dependency
			pkg.Indirect = false
			visited[pkg.ID] = pkg
			break
		}
	}

	// Identify indirect dependencies
	for _, pkg := range visited {
		walkIndirectDependencies(pkg, pkgIDs, visited)
	}

	visitedPkgs := maps.Values(visited)
	sort.Sort(types.Packages(visitedPkgs))

	// Include only the packages we visited so that we don't include any deps from the [extras] section
	app.Libraries = visitedPkgs
	return nil
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

// Marks all indirect dependencies as indirect. Starts from `rootPkg`. Visited deps are added to `visited`.
func walkIndirectDependencies(rootPkg types.Package, allPkgIDs map[string]types.Package, visited map[string]types.Package) {
	for _, pkgID := range rootPkg.DependsOn {
		if _, ok := visited[pkgID]; ok {
			continue
		}

		dep, ok := allPkgIDs[pkgID]
		if !ok {
			continue
		}

		dep.Indirect = true
		visited[dep.ID] = dep
		walkIndirectDependencies(dep, allPkgIDs, visited)
	}
}
