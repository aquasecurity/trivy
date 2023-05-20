package julia

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-version/pkg/semver"
	goversion "github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	fmt.Println("initing julia analyzer")
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

func newJuliaAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &juliaAnalyzer{
		lockParser: NewParser(),
		comparer:   compare.GenericComparer{},
	}, nil
}

func (a juliaAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	fmt.Println("julia PostAnalyze")
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

		// Parse Project.toml alongside Manifest.toml to identify the direct dependencies
		if err = a.removeDevDependencies(input.FS, filepath.Dir(path), app); err != nil {
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

func (a juliaAnalyzer) removeDevDependencies(fsys fs.FS, dir string, app *types.Application) error {
	juliaTOMLPath := filepath.Join(dir, types.JuliaProject)
	directDeps, err := a.parseJuliaProject(fsys, juliaTOMLPath)
	if errors.Is(err, fs.ErrNotExist) {
		log.Logger.Debugf("Julia: %s not found", juliaTOMLPath)
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %s: %w", juliaTOMLPath, err)
	}

	// Project.toml file can contain same libraries with different versions.
	// Save versions separately for version comparison by comparator
	pkgIDs := lo.SliceToMap(app.Libraries, func(pkg types.Package) (string, types.Package) {
		return pkg.ID, pkg
	})

	// Identify direct dependencies
	pkgs := map[string]types.Package{}
	for uuid, constraint := range directDeps {
		for _, pkg := range app.Libraries {
			if pkg.ID != uuid {
				continue
			}

			if match, err := a.matchVersion(pkg.Version, constraint); err != nil {
				log.Logger.Warnf("Unable to match Julia version: package: %s, error: %s", pkg.ID, err)
				continue
			} else if match {
				// Mark as a direct dependency
				pkg.Indirect = false
				pkgs[pkg.ID] = pkg
				break
			}
		}
	}

	// Walk indirect dependencies
	// Since it starts from direct dependencies, devDependencies will not appear in this walk.
	for _, pkg := range pkgs {
		a.walkIndirectDependencies(pkg, pkgIDs, pkgs)
	}

	pkgSlice := maps.Values(pkgs)
	sort.Sort(types.Packages(pkgSlice))

	// Save only prod libraries
	app.Libraries = pkgSlice
	return nil
}

type juliaToml struct {
	Name    string `toml:"name"`
	UUID    string `toml:"uuid`
	Version string `toml:"version"`
	Deps    Deps   `toml:"deps"`
	Compat  Compat `toml:"compat"`
}

type Deps map[string]string

type Compat map[string]string

func (a juliaAnalyzer) parseJuliaProject(fsys fs.FS, path string) (map[string]string, error) {
	// Parse Project.toml
	f, err := fsys.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	tomlFile := juliaToml{}
	deps := map[string]string{}
	_, err = toml.NewDecoder(f).Decode(&tomlFile)
	if err != nil {
		return nil, xerrors.Errorf("toml decode error: %w", err)
	}

	// Julia projects don't need to have dependencies, so ensure `Deps` is non-nil to avoid panics
	dependencies := Deps{}
	maps.Copy(dependencies, tomlFile.Deps)

	// Julia projects don't need to have compat, so ensure `Compat` is non-nil to avoid panics
	compat := Compat{}
	maps.Copy(compat, tomlFile.Compat)

	for depName, uuid := range dependencies {
		// If there is no compat, use an empty specifier
		deps[uuid] = ""

		// Find the compat if it exists
		for compatName, spec := range compat {
			if depName == compatName {
				deps[uuid] = spec
			}
		}
	}

	return deps, nil
}

func (a juliaAnalyzer) walkIndirectDependencies(pkg types.Package, pkgIDs map[string]types.Package, deps map[string]types.Package) {
	for _, pkgID := range pkg.DependsOn {
		if _, ok := deps[pkgID]; ok {
			continue
		}

		dep, ok := pkgIDs[pkgID]
		if !ok {
			continue
		}

		dep.Indirect = true
		deps[dep.ID] = dep
		a.walkIndirectDependencies(dep, pkgIDs, deps)
	}
}

// cf. https://doc.rust-lang.org/julia/reference/specifying-dependencies.html
func (a juliaAnalyzer) matchVersion(currentVersion, constraint string) (bool, error) {
	// `` == `^` - https://doc.rust-lang.org/julia/reference/specifying-dependencies.html#caret-requirements
	// Add `^` for correct version comparison
	//   - 1.2.3 -> ^1.2.3
	//   - 1.2.* -> 1.2.*
	//   - ^1.2  -> ^1.2
	if _, err := goversion.Parse(constraint); err == nil {
		constraint = fmt.Sprintf("^%s", constraint)
	}

	ver, err := semver.Parse(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("version error (%s): %s", currentVersion, err)
	}

	c, err := semver.NewConstraints(constraint)
	if err != nil {
		return false, xerrors.Errorf("constraint error (%s): %s", currentVersion, err)
	}

	return c.Check(ver), nil
}
