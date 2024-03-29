package cargo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-version/pkg/semver"
	goversion "github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/rust/cargo"
	godeptypes "github.com/aquasecurity/trivy/pkg/dependency/types"
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

	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, d fs.DirEntry, r io.Reader) error {
		// Parse Cargo.lock
		app, err := a.parseCargoLock(filePath, r)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Parse Cargo.toml alongside Cargo.lock to identify the direct dependencies
		if err = a.removeDevDependencies(input.FS, path.Dir(filePath), app); err != nil {
			log.Logger.Warnf("Unable to parse %q to identify direct dependencies: %s", path.Join(path.Dir(filePath), types.CargoToml), err)
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

func (a cargoAnalyzer) parseCargoLock(filePath string, r io.Reader) (*types.Application, error) {
	return language.Parse(types.Cargo, filePath, r, a.lockParser)
}

func (a cargoAnalyzer) removeDevDependencies(fsys fs.FS, dir string, app *types.Application) error {
	cargoTOMLPath := path.Join(dir, types.CargoToml)
	directDeps, err := a.parseRootCargoTOML(fsys, cargoTOMLPath)
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
	pkgs := make(map[string]types.Package)
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
	Workspace    cargoTomlWorkspace                 `toml:"workspace"`
}

type cargoTomlWorkspace struct {
	Dependencies Dependencies `toml:"dependencies"`
	Members      []string     `toml:"members"`
}

type Dependencies map[string]interface{}

// parseRootCargoTOML parses top-level Cargo.toml and returns dependencies.
// It also parses workspace members and their dependencies.
func (a cargoAnalyzer) parseRootCargoTOML(fsys fs.FS, filePath string) (map[string]string, error) {
	dependencies, members, err := parseCargoTOML(fsys, filePath)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse %s: %w", filePath, err)
	}
	// According to Cargo workspace RFC, workspaces can't be nested:
	// https://github.com/nox/rust-rfcs/blob/master/text/1525-cargo-workspace.md#validating-a-workspace
	for _, member := range members {
		memberPath := path.Join(path.Dir(filePath), member, types.CargoToml)
		memberDeps, _, err := parseCargoTOML(fsys, memberPath)
		if err != nil {
			log.Logger.Warnf("Unable to parse %q: %s", memberPath, err)
			continue
		}
		// Member dependencies shouldn't overwrite dependencies from root cargo.toml file
		maps.Copy(memberDeps, dependencies)
		dependencies = memberDeps
	}

	deps := make(map[string]string)
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

func (a cargoAnalyzer) walkIndirectDependencies(pkg types.Package, pkgIDs, deps map[string]types.Package) {
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

func parseCargoTOML(fsys fs.FS, filePath string) (Dependencies, []string, error) {
	// Parse Cargo.toml
	f, err := fsys.Open(filePath)
	if err != nil {
		return nil, nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	var tomlFile cargoToml
	// There are cases when toml file doesn't include `Dependencies` field (then map will be nil).
	// e.g. when only `workspace.Dependencies` are used
	// declare `dependencies` to avoid panic
	dependencies := Dependencies{}
	if _, err = toml.NewDecoder(f).Decode(&tomlFile); err != nil {
		return nil, nil, xerrors.Errorf("toml decode error: %w", err)
	}

	maps.Copy(dependencies, tomlFile.Dependencies)

	// https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#platform-specific-dependencies
	for _, target := range tomlFile.Target {
		maps.Copy(dependencies, target["dependencies"])
	}

	// https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#inheriting-a-dependency-from-a-workspace
	maps.Copy(dependencies, tomlFile.Workspace.Dependencies)
	// https://doc.rust-lang.org/cargo/reference/workspaces.html#the-members-and-exclude-fields
	return dependencies, tomlFile.Workspace.Members, nil
}
