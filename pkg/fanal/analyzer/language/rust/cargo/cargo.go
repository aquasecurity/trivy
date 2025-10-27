package cargo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-version/pkg/semver"
	goversion "github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/rust/cargo"
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
	logger     *log.Logger
	lockParser language.Parser
	comparer   compare.GenericComparer
}

func newCargoAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &cargoAnalyzer{
		logger:     log.WithPrefix("cargo"),
		lockParser: cargo.NewParser(),
		comparer:   compare.GenericComparer{},
	}, nil
}

func (a cargoAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.CargoLock || input.FilePatterns.Match(path)
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		// Parse Cargo.lock
		app, err := a.parseCargoLock(ctx, filePath, r)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Parse Cargo.toml alongside Cargo.lock to identify the direct dependencies
		if err = a.removeDevDependencies(input.FS, path.Dir(filePath), app); err != nil {
			a.logger.Warn("Unable to parse Cargo.toml q to identify direct dependencies",
				log.FilePath(path.Join(path.Dir(filePath), types.CargoToml)), log.Err(err))
		}
		sort.Sort(app.Packages)
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

func (a cargoAnalyzer) parseCargoLock(ctx context.Context, filePath string, r io.Reader) (*types.Application, error) {
	return language.Parse(ctx, types.Cargo, filePath, r, a.lockParser)
}

func (a cargoAnalyzer) removeDevDependencies(fsys fs.FS, dir string, app *types.Application) error {
	cargoTOMLPath := path.Join(dir, types.CargoToml)
	root, workspaces, directDeps, err := a.parseRootCargoTOML(fsys, cargoTOMLPath)
	if errors.Is(err, fs.ErrNotExist) {
		a.logger.Debug("Cargo.toml not found", log.FilePath(cargoTOMLPath))
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %s: %w", cargoTOMLPath, err)
	}

	// Cargo.toml file can contain same packages with different versions.
	// Save versions separately for version comparison by comparator
	pkgIDs := lo.SliceToMap(app.Packages, func(pkg types.Package) (string, types.Package) {
		return pkg.ID, pkg
	})

	// Identify direct dependencies
	pkgs := make(map[string]types.Package)
	for name, constraint := range directDeps {
		for _, pkg := range app.Packages {
			if pkg.Name != name {
				continue
			}

			if match, err := a.matchVersion(pkg.Version, constraint); err != nil {
				a.logger.Warn("Unable to match Cargo version", log.String("package", pkg.ID), log.Err(err))
				continue
			} else if match {
				// Mark as a direct dependency
				pkg.Indirect = false
				pkg.Relationship = types.RelationshipDirect
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

	// Identify root and workspace packages
	for pkgID, pkg := range pkgIDs {
		switch {
		case pkgID == root:
			pkg.Relationship = types.RelationshipRoot
		case slices.Contains(workspaces, pkgID):
			pkg.Relationship = types.RelationshipWorkspace
		default:
			continue
		}

		// Root/workspace package may include dev dependencies in lock file, so we need to remove them.
		pkg.DependsOn = lo.Filter(pkg.DependsOn, func(dep string, _ int) bool {
			_, ok := pkgs[dep]
			return ok
		})
		pkgs[pkgID] = pkg
	}

	// Cargo allows creating cargo.toml files without name and version.
	// In this case, the lock file will not include this package.
	// e.g. when root cargo.toml contains only workspaces.
	// So we have to add it ourselves, and the ID in this case will be the hash of the toml file.
	if _, ok := pkgs[root]; !ok {
		pkgs[root] = types.Package{
			ID:           root,
			Relationship: types.RelationshipRoot,
			DependsOn:    workspaces,
		}
	}

	pkgSlice := lo.Values(pkgs)
	sort.Sort(types.Packages(pkgSlice))

	// Save only prod packages
	app.Packages = pkgSlice
	return nil
}

type cargoToml struct {
	Package      Package                            `toml:"package"`
	Dependencies Dependencies                       `toml:"dependencies"`
	Target       map[string]map[string]Dependencies `toml:"target"`
	Workspace    cargoTomlWorkspace                 `toml:"workspace"`
}

type Package struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type cargoTomlWorkspace struct {
	Dependencies Dependencies `toml:"dependencies"`
	Members      []string     `toml:"members"`
}

type Dependencies map[string]any

// parseRootCargoTOML parses top-level Cargo.toml and returns dependencies.
// It also parses workspace members and their dependencies.
func (a cargoAnalyzer) parseRootCargoTOML(fsys fs.FS, filePath string) (string, []string, map[string]string, error) {
	rootPkg, dependencies, members, err := a.parseCargoTOML(fsys, filePath)
	if err != nil {
		return "", nil, nil, xerrors.Errorf("unable to parse %s: %w", filePath, err)
	}

	// According to Cargo workspace RFC, workspaces can't be nested:
	// https://github.com/nox/rust-rfcs/blob/master/text/1525-cargo-workspace.md#validating-a-workspace
	var workspaces []string
	for _, member := range members {
		memberPath := path.Join(path.Dir(filePath), member, types.CargoToml)
		memberPkg, memberDeps, _, err := a.parseCargoTOML(fsys, memberPath)
		if err != nil {
			a.logger.Warn("Unable to parse Cargo.toml", log.String("member_path", memberPath), log.Err(err))
			continue
		}
		workspaces = append(workspaces, memberPkg)

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
		case map[string]any:
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

	return rootPkg, workspaces, deps, nil
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
		dep.Relationship = types.RelationshipIndirect
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

func (a cargoAnalyzer) parseCargoTOML(fsys fs.FS, filePath string) (string, Dependencies, []string, error) {
	// Parse Cargo.toml
	f, err := fsys.Open(filePath)
	if err != nil {
		return "", nil, nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	var tomlFile cargoToml
	// There are cases when toml file doesn't include `Dependencies` field (then map will be nil).
	// e.g. when only `workspace.Dependencies` are used
	// declare `dependencies` to avoid panic
	dependencies := Dependencies{}
	if _, err = toml.NewDecoder(f).Decode(&tomlFile); err != nil {
		return "", nil, nil, xerrors.Errorf("toml decode error: %w", err)
	}

	pkgID := a.packageID(tomlFile)

	maps.Copy(dependencies, tomlFile.Dependencies)

	// https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#platform-specific-dependencies
	for _, target := range tomlFile.Target {
		maps.Copy(dependencies, target["dependencies"])
	}

	// https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#inheriting-a-dependency-from-a-workspace
	maps.Copy(dependencies, tomlFile.Workspace.Dependencies)
	// https://doc.rust-lang.org/cargo/reference/workspaces.html#the-members-and-exclude-fields
	return pkgID, dependencies, tomlFile.Workspace.Members, nil
}

// packageID builds PackageID by Package name and version.
// If name is empty - use hash of cargoToml.
func (a cargoAnalyzer) packageID(cargoToml cargoToml) string {
	if cargoToml.Package.Name != "" {
		return dependency.ID(types.Cargo, cargoToml.Package.Name, cargoToml.Package.Version)
	}

	hash, err := hashstructure.Hash(cargoToml, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:         true,
		IgnoreZeroValue: true,
	})
	if err != nil {
		a.logger.Warn("unable to hash package", log.String("package", cargoToml.Package.Name), log.Err(err))
	}

	return strconv.FormatUint(hash, 16)
}
