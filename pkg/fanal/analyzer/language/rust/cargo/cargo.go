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
			a.logger.Warn("Unable to parse Cargo.toml to identify direct dependencies",
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
	root, workspaces, owners, err := a.parseRootCargoTOML(fsys, cargoTOMLPath)
	if errors.Is(err, fs.ErrNotExist) {
		a.logger.Debug("Cargo.toml not found", log.FilePath(cargoTOMLPath))
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %s: %w", cargoTOMLPath, err)
	}

	// Index lock packages by ID for quick lookup.
	pkgIDs := lo.SliceToMap(app.Packages, func(pkg types.Package) (string, types.Package) {
		return pkg.ID, pkg
	})

	// Identify direct dependencies.
	// The version Cargo selected is already recorded in the lock file: the root package
	// and every workspace member list their direct dependencies (including dev/build ones)
	// in `dependencies`, which the lock parser resolves to exact package IDs in DependsOn.
	// So for each owner we keep the DependsOn IDs whose name is declared in that owner's
	// [dependencies] / [target.*.dependencies]. This also covers git/path/workspace-inherited
	// dependencies that have no version string in Cargo.toml.
	pkgs := make(map[string]types.Package)
	for _, owner := range owners {
		ownerPkg, ok := pkgIDs[owner.id]
		if !ok {
			// The owner may not have a lock entry (e.g. a purely virtual workspace root).
			continue
		}
		a.selectDirectDependencies(ownerPkg, owner.deps, pkgIDs, pkgs)
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
	Version any    `toml:"version"`
}

type cargoTomlWorkspace struct {
	Dependencies Dependencies `toml:"dependencies"`
	Members      []string     `toml:"members"`
	Package      struct {
		Version string `toml:"version"`
	} `toml:"package"`
}

type Dependencies map[string]any

// cargoTOMLResult holds the parsed data of a single Cargo.toml file.
type cargoTOMLResult struct {
	// pkgID is the lock file package ID of the manifest's package.
	pkgID string
	// dependencies are the manifest's [dependencies] and [target.*.dependencies].
	dependencies Dependencies
	// members are the workspace member paths declared in [workspace].members.
	members []string
	// workspaceVersion is the effective [workspace.package] version.
	workspaceVersion string
	// workspaceDependencies are the [workspace.dependencies] definitions.
	workspaceDependencies Dependencies
}

// dependencyOwner represents a package (the root package or a workspace member)
// that declares its own direct dependencies in a Cargo.toml.
type dependencyOwner struct {
	// id is the lock file package ID of the owner.
	id string
	// deps maps a declared dependency name to its version constraint.
	// The constraint is empty when the dependency has no version string
	// (git/path/workspace-inherited dependencies).
	deps map[string]string
}

// parseRootCargoTOML parses top-level Cargo.toml and returns the root package ID,
// the workspace member package IDs, and the list of dependency owners (the root
// package plus each workspace member) with the dependency names each one declares.
func (a cargoAnalyzer) parseRootCargoTOML(fsys fs.FS, filePath string) (string, []string, []dependencyOwner, error) {
	root, err := a.parseCargoTOML(fsys, filePath, "")
	if err != nil {
		return "", nil, nil, xerrors.Errorf("unable to parse %s: %w", filePath, err)
	}
	rootPkg := root.pkgID

	var owners []dependencyOwner
	// The root package declares its own dependencies (single-crate projects and
	// projects that are both a package and a workspace root).
	// The root also owns [workspace.dependencies]: unlike members, the workspace root
	// itself may use them directly, and the lock file already restricts the root's
	// DependsOn to the crates it actually pulls in.
	rootDeclared := resolveDeclaredDeps(root.dependencies, root.workspaceDependencies)
	for name, value := range root.workspaceDependencies {
		if _, ok := rootDeclared[name]; !ok {
			rootDeclared[name] = workspaceConstraint(value)
		}
	}
	owners = append(owners, dependencyOwner{
		id:   rootPkg,
		deps: rootDeclared,
	})

	// According to Cargo workspace RFC, workspaces can't be nested:
	// https://github.com/nox/rust-rfcs/blob/master/text/1525-cargo-workspace.md#validating-a-workspace
	var workspaces []string
	for _, member := range root.members {
		memberPath := path.Join(path.Dir(filePath), member, types.CargoToml)

		// Cargo workspaces can be globs:
		// https://github.com/rust-lang/cargo/pull/3979
		resolvedPaths, err := fs.Glob(fsys, memberPath)
		if err != nil {
			a.logger.Warn("Invalid glob pattern in Cargo.toml member paths", log.String("member_path", memberPath), log.Err(err))
			continue
		}

		if len(resolvedPaths) == 0 {
			a.logger.Warn("Unable to find matching Cargo.toml files", log.String("member_path", memberPath))
			continue
		}

		for _, pkg := range resolvedPaths {
			member, err := a.parseCargoTOML(fsys, pkg, root.workspaceVersion)
			if err != nil {
				a.logger.Warn("Unable to parse Cargo.toml", log.String("member_path", pkg), log.Err(err))
				continue
			}
			workspaces = append(workspaces, member.pkgID)
			owners = append(owners, dependencyOwner{
				id:   member.pkgID,
				deps: resolveDeclaredDeps(member.dependencies, root.workspaceDependencies),
			})
		}
	}

	return rootPkg, workspaces, owners, nil
}

// resolveDeclaredDeps turns the raw [dependencies] / [target.*.dependencies] entries
// of a single manifest into a map of dependency name -> version constraint.
// The constraint is empty when no version string is present (git/path/workspace-inherited
// dependencies). For `name = { workspace = true }` entries, the version constraint is
// taken from the matching [workspace.dependencies] definition when it is a string.
func resolveDeclaredDeps(dependencies, workspaceDeps Dependencies) map[string]string {
	deps := make(map[string]string)
	for name, value := range dependencies {
		switch ver := value.(type) {
		case string:
			// e.g. regex = "1.5"
			deps[name] = ver
		case map[string]any:
			if ws, ok := ver["workspace"]; ok {
				if b, ok := ws.(bool); ok && b {
					// e.g. regex = { workspace = true }
					// The dependency is declared by this owner; reuse the workspace
					// definition only to recover a version constraint if it has one.
					deps[name] = workspaceConstraint(workspaceDeps[name])
					continue
				}
			}
			// e.g. serde = { version = "1.0", features = ["derive"] }
			// git/path dependencies have no version key and keep an empty constraint.
			deps[name] = versionConstraint(ver)
		}
	}
	return deps
}

// workspaceConstraint extracts the version constraint from a [workspace.dependencies] entry.
func workspaceConstraint(value any) string {
	switch ver := value.(type) {
	case string:
		return ver
	case map[string]any:
		return versionConstraint(ver)
	default:
		return ""
	}
}

// versionConstraint returns the `version` string of a table dependency, or "" if absent.
func versionConstraint(table map[string]any) string {
	if v, ok := table["version"]; ok {
		if vv, ok := v.(string); ok {
			return vv
		}
	}
	return ""
}

// selectDirectDependencies marks the direct dependencies of a single owner package.
// It keeps only the owner's DependsOn IDs whose name is declared in the owner's manifest.
// When several versions of the same declared name are reachable, the version constraint
// (when present) is used to disambiguate, preserving the behavior added in #3919.
func (a cargoAnalyzer) selectDirectDependencies(owner types.Package, declared map[string]string, pkgIDs, pkgs map[string]types.Package) {
	// Group the owner's resolved dependencies by name so we can tell single-version
	// crates (accepted by name) apart from multi-version crates (disambiguated by constraint).
	byName := make(map[string][]types.Package)
	for _, depID := range owner.DependsOn {
		dep, ok := pkgIDs[depID]
		if !ok {
			continue
		}
		if _, declaredDep := declared[dep.Name]; !declaredDep {
			continue
		}
		byName[dep.Name] = append(byName[dep.Name], dep)
	}

	for name, candidates := range byName {
		constraint := declared[name]
		for _, pkg := range candidates {
			// When only one version is reachable, accept it by name (the core fix:
			// git/path/workspace-inherited deps have no version constraint).
			if len(candidates) > 1 && constraint != "" {
				if match, err := a.matchVersion(pkg.Version, constraint); err != nil {
					a.logger.Warn("Unable to match Cargo version", log.String("package", pkg.ID), log.Err(err))
					continue
				} else if !match {
					continue
				}
			}
			pkg.Indirect = false
			pkg.Relationship = types.RelationshipDirect
			pkgs[pkg.ID] = pkg
		}
	}
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

func (a cargoAnalyzer) parseCargoTOML(fsys fs.FS, filePath, workspaceVersion string) (cargoTOMLResult, error) {
	// Parse Cargo.toml
	f, err := fsys.Open(filePath)
	if err != nil {
		return cargoTOMLResult{}, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	var tomlFile cargoToml
	var pkgVersion string
	// There are cases when toml file doesn't include `Dependencies` field (then map will be nil).
	// e.g. when only `workspace.Dependencies` are used
	// declare `dependencies` to avoid panic
	dependencies := Dependencies{}
	if _, err = toml.NewDecoder(f).Decode(&tomlFile); err != nil {
		return cargoTOMLResult{}, xerrors.Errorf("toml decode error: %w", err)
	}

	// https://rust-lang.github.io/rfcs/2906-cargo-workspace-deduplicate.html
	if workspaceVersion == "" {
		workspaceVersion = tomlFile.Workspace.Package.Version
	}

	switch ver := tomlFile.Package.Version.(type) {
	// In case of purely virtual cargo workspace version only lives in `workspace.package.version`
	case nil:
		pkgVersion = workspaceVersion
	// We assume a proper version string was used, like: `0.1.0`
	// Empty version is not allowed in Cargo.toml
	// cf. https://github.com/aquasecurity/trivy/pull/10011#discussion_r2740743095
	case string:
		pkgVersion = ver
	// There are cases when `package.version` uses `version.workspace = true`,
	// which must inherit the version from `workspace.version` or workspaceVersion (from root Cargo.toml)
	case map[string]any:
		if verWorkspace, found := ver["workspace"]; found {
			if wv, ok := verWorkspace.(bool); ok && wv {
				pkgVersion = workspaceVersion
			}
		}
	}

	pkgID := a.packageID(tomlFile, pkgVersion)

	maps.Copy(dependencies, tomlFile.Dependencies)

	// https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#platform-specific-dependencies
	for _, target := range tomlFile.Target {
		maps.Copy(dependencies, target["dependencies"])
	}

	// [workspace.dependencies] are NOT direct dependencies of the workspace root or of any
	// member on their own: a member becomes a direct dependent only when it declares the
	// dependency (with `workspace = true`). They are returned separately so the constraint
	// can be recovered for `workspace = true` entries.
	// https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#inheriting-a-dependency-from-a-workspace
	// https://doc.rust-lang.org/cargo/reference/workspaces.html#the-members-and-exclude-fields
	return cargoTOMLResult{
		pkgID:                 pkgID,
		dependencies:          dependencies,
		members:               tomlFile.Workspace.Members,
		workspaceVersion:      workspaceVersion,
		workspaceDependencies: tomlFile.Workspace.Dependencies,
	}, nil
}

// packageID builds PackageID by Package name and version.
// If name is empty - use hash of cargoToml.
func (a cargoAnalyzer) packageID(cargoToml cargoToml, pkgVersion string) string {
	if cargoToml.Package.Name != "" {
		return dependency.ID(types.Cargo, cargoToml.Package.Name, pkgVersion)
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
