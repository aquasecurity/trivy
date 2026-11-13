package uv

import (
	"context"
	"slices"
	"sort"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Lock struct {
	Manifest Manifest  `toml:"manifest"`
	Packages []Package `toml:"package"`
}

// packages groups the packages by name. A lockfile with a forked resolution
// contains several versions of the same package, e.g. one per Python version.
func (l Lock) packages() map[string][]Package {
	return lo.GroupBy(l.Packages, func(pkg Package) string {
		return pkg.Name
	})
}

// resolve returns the locked packages a dependency refers to.
// uv records the version of a dependency when several versions of the package are locked.
func resolve(dep Dependency, packages map[string][]Package) []Package {
	return lo.Filter(packages[dep.Name], func(pkg Package, _ int) bool {
		return dep.Version == "" || pkg.Version == dep.Version
	})
}

type Manifest struct {
	Members []string `toml:"members"`
}

// prodDeps returns the IDs of all production dependencies: every package reachable from
// the root package or a workspace member by following non-dev dependencies.
func prodDeps(root string, workspaces set.Set[string], packages map[string][]Package) set.Set[string] {
	visited := set.New[string]()
	if root != "" {
		for _, pkg := range packages[root] {
			walkPackageDeps(pkg, packages, visited)
		}
	}
	for name := range workspaces.Iter() {
		for _, pkg := range packages[name] {
			walkPackageDeps(pkg, packages, visited)
		}
	}
	return visited
}

func walkPackageDeps(pkg Package, packages map[string][]Package, visited set.Set[string]) {
	pkgID := packageID(pkg.Name, pkg.Version)
	if visited.Contains(pkgID) {
		return
	}
	visited.Append(pkgID)
	for _, dep := range pkg.nonDevDeps() {
		for _, depPkg := range resolve(dep, packages) {
			walkPackageDeps(depPkg, packages, visited)
		}
	}
}

// rootAndWorkspaces walks the lockfile packages once and returns the name of the root
// package (empty if there is none), the set of workspace member names, and the set of
// direct dependency names collected from the root and every workspace member. The root
// and workspaces are the entry points of the dependency graph: everything reachable from
// them is a production dependency.
func (l Lock) rootAndWorkspaces() (root string, workspaces, directDeps set.Set[string], err error) {
	workspaces = set.New[string]()
	directDeps = set.New[string]()

	for _, pkg := range l.Packages {
		switch {
		case pkg.isRoot():
			if root != "" {
				return "", nil, nil, xerrors.New("uv lockfile must contain 1 root package")
			}
			root = pkg.Name
			directDeps.Append(pkg.directDeps().names().Items()...)
		case slices.Contains(l.Manifest.Members, pkg.Name):
			workspaces.Append(pkg.Name)
			directDeps.Append(pkg.directDeps().names().Items()...)
		}
	}

	return root, workspaces, directDeps, nil
}

type Package struct {
	Name                 string                  `toml:"name"`
	Version              string                  `toml:"version"`
	Source               Source                  `toml:"source"`
	Dependencies         Dependencies            `toml:"dependencies"`
	DevDependencies      map[string]Dependencies `toml:"dev-dependencies"`
	OptionalDependencies map[string]Dependencies `toml:"optional-dependencies"`
}

func (p Package) directDeps() Dependencies {
	deps := p.nonDevDeps()
	for _, groupDeps := range p.DevDependencies {
		deps = append(deps, groupDeps...)
	}
	return deps
}

func (p Package) nonDevDeps() Dependencies {
	deps := slices.Clone(p.Dependencies)
	for _, groupDeps := range p.OptionalDependencies {
		deps = append(deps, groupDeps...)
	}
	return deps
}

type Dependencies []Dependency

func (d Dependencies) names() set.Set[string] {
	return set.New(lo.Map(d, func(dep Dependency, _ int) string {
		return dep.Name
	})...)
}

// https://github.com/astral-sh/uv/blob/f7d647e81d7e1e3be189324b06024ed2057168e6/crates/uv-resolver/src/lock/mod.rs#L572-L579
func (p Package) isRoot() bool {
	return p.Source.Editable == "." || p.Source.Virtual == "."
}

type Source struct {
	Editable string `toml:"editable"`
	Virtual  string `toml:"virtual"`
}

type Dependency struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lock Lock
	if _, err := toml.NewDecoder(r).Decode(&lock); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode uv lock file: %w", err)
	}

	root, workspaces, directDeps, err := lock.rootAndWorkspaces()
	if err != nil {
		return nil, nil, err
	}

	packages := lock.packages()

	// Production dependencies are the packages reachable from the root package
	// or, for workspace lockfiles, any workspace member package.
	prodDeps := prodDeps(root, workspaces, packages)

	var (
		pkgs ftypes.Packages
		deps ftypes.Dependencies
	)

	for _, pkg := range lock.Packages {
		pkgID := packageID(pkg.Name, pkg.Version)
		relationship := ftypes.RelationshipIndirect
		switch {
		case pkg.Name == root:
			relationship = ftypes.RelationshipRoot
		case workspaces.Contains(pkg.Name):
			relationship = ftypes.RelationshipWorkspace
		case directDeps.Contains(pkg.Name):
			relationship = ftypes.RelationshipDirect
		}

		pkgs = append(pkgs, ftypes.Package{
			ID:           pkgID,
			Name:         pkg.Name,
			Version:      pkg.Version,
			Relationship: relationship,
			Dev:          !prodDeps.Contains(pkgID),
		})

		dependsOn := set.New[string]()
		for _, dep := range pkg.directDeps() {
			for _, depPkg := range resolve(dep, packages) {
				dependsOn.Append(packageID(depPkg.Name, depPkg.Version))
			}
		}
		// The root package depends on every workspace member
		if pkg.Name == root {
			for name := range workspaces.Iter() {
				for _, member := range packages[name] {
					dependsOn.Append(packageID(member.Name, member.Version))
				}
			}
		}

		if dependsOn.Size() > 0 {
			dependsOnIDs := dependsOn.Items()
			sort.Strings(dependsOnIDs)
			deps = append(deps, ftypes.Dependency{
				ID:        pkgID,
				DependsOn: dependsOnIDs,
			})
		}
	}

	sort.Sort(pkgs)
	sort.Sort(deps)
	return pkgs, deps, nil
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Uv, name, version)
}
