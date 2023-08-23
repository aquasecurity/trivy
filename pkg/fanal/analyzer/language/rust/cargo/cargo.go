package cargo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"

	"github.com/aquasecurity/go-dep-parser/pkg/rust/cargo"
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
	analyzer.RegisterPostAnalyzer(analyzer.TypeCargo, newCargoAnalyzer)
}

const version = 1

var requiredFiles = []string{
	types.CargoLock,
	types.CargoToml,
}

type cargoAnalyzer struct {
	lockParser godeptypes.Parser
	comparer   compare.GenericComparer
}

func newCargoAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &cargoAnalyzer{
		lockParser: cargo.NewParser(),
		comparer:   compare.GenericComparer{},
	}, nil
}

func (a cargoAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == types.CargoLock
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, d fs.DirEntry, r io.Reader) error {
		// Parse Cargo.lock
		app, err := a.parseCargoLock(path, r)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Parse Cargo.toml alongside Cargo.lock to identify the direct dependencies
		if err = a.removeDevDependencies(input.FS, filepath.Dir(path), app); err != nil {
			log.Logger.Warnf("Unable to parse %q to identify direct dependencies: %s", filepath.Join(filepath.Dir(path), types.CargoToml), err)
		}
		sort.Sort(app.Libraries)
		apps = append(apps, *app)

		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("cargo walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a cargoAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return slices.Contains(requiredFiles, fileName)
}

func (a cargoAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCargo
}

func (a cargoAnalyzer) Version() int {
	return version
}

func (a cargoAnalyzer) parseCargoLock(path string, r io.Reader) (*types.Application, error) {
	return language.Parse(types.Cargo, path, r, a.lockParser)
}

func (a cargoAnalyzer) removeDevDependencies(fsys fs.FS, dir string, app *types.Application) error {
	cargoTOMLPath := filepath.Join(dir, types.CargoToml)
	directDeps, err := a.parseCargoTOML(fsys, cargoTOMLPath)
	if errors.Is(err, fs.ErrNotExist) {
		log.Logger.Debugf("Cargo: %s not found", cargoTOMLPath)
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %s: %w", cargoTOMLPath, err)
	}

	// Cargo.toml file can contain same libraries with different versions.
	// Save versions separately for version comparison by comparator
	pkgIDs := lo.SliceToMap(app.Libraries, func(pkg types.Package) (string, types.Package) {
		return pkg.ID, pkg
	})

	// Identify direct dependencies
	pkgs := map[string]types.Package{}
	for name, constraint := range directDeps {
		for _, pkg := range app.Libraries {
			if pkg.Name != name {
				continue
			}

			if match, err := a.matchVersion(pkg.Version, constraint); err != nil {
				log.Logger.Warnf("Unable to match Cargo version: package: %s, error: %s", pkg.ID, err)
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

type cargoToml struct {
	Dependencies Dependencies                       `toml:"dependencies"`
	Target       map[string]map[string]Dependencies `toml:"target"`
	Workspace    map[string]Dependencies            `toml:"workspace"`
}

type Dependencies map[string]interface{}

func (a cargoAnalyzer) parseCargoTOML(fsys fs.FS, path string) (map[string]string, error) {
	// Parse Cargo.json
	f, err := fsys.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	tomlFile := cargoToml{}
	deps := map[string]string{}
	_, err = toml.NewDecoder(f).Decode(&tomlFile)
	if err != nil {
		return nil, xerrors.Errorf("toml decode error: %w", err)
	}

	// There are cases when toml file doesn't include `Dependencies` field (then map will be nil).
	// e.g. when only `workspace.Dependencies` are used
	// declare `dependencies` to avoid panic
	dependencies := Dependencies{}
	maps.Copy(dependencies, tomlFile.Dependencies)

	// https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#platform-specific-dependencies
	for _, target := range tomlFile.Target {
		maps.Copy(dependencies, target["dependencies"])
	}

	// https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#inheriting-a-dependency-from-a-workspace
	maps.Copy(dependencies, tomlFile.Workspace["dependencies"])

	for name, value := range dependencies {
		switch ver := value.(type) {
		case string:
			// e.g. regex = "1.5"
			deps[name] = ver
		case map[string]interface{}:
			// e.g. serde = { version = "1.0", features = ["derive"] }
			for k, v := range ver {
				if k == "version" {
					if vv, ok := v.(string); ok {
						deps[name] = vv
					}
					break
				}
			}
		}
	}

	return deps, nil
}

func (a cargoAnalyzer) walkIndirectDependencies(pkg types.Package, pkgIDs map[string]types.Package, deps map[string]types.Package) {
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

// cf. https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html
func (a cargoAnalyzer) matchVersion(currentVersion, constraint string) (bool, error) {
	// `` == `^` - https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#caret-requirements
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
