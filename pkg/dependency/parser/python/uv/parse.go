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

func prodDeps(root Package, packages map[string][]Package) set.Set[string] {
	visited := set.New[string]()
	walkPackageDeps(root, packages, visited)
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

func (l Lock) root() (Package, error) {
	var pkgs []Package
	for _, pkg := range l.Packages {
		if pkg.isRoot() {
			pkgs = append(pkgs, pkg)
		}
	}

	// lock file must include root package
	// cf. https://github.com/astral-sh/uv/blob/f80ddf10b63c3e7b421ca4658e63f97db1e0378c/crates/uv/src/commands/project/lock.rs#L933-L936
	if len(pkgs) != 1 {
		return Package{}, xerrors.New("uv lockfile must contain 1 root package")
	}

	return pkgs[0], nil
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

	rootPackage, err := lock.root()
	if err != nil {
		return nil, nil, err
	}

	packages := lock.packages()
	directDeps := rootPackage.directDeps().names()

	// Since each lockfile contains a root package with a list of direct dependencies,
	// we can identify all production dependencies by traversing the dependency graph
	// and collecting all the dependencies that are reachable from the root.
	prodDeps := prodDeps(rootPackage, packages)

	var (
		pkgs ftypes.Packages
		deps ftypes.Dependencies
	)

	for _, pkg := range lock.Packages {
		pkgID := packageID(pkg.Name, pkg.Version)
		relationship := ftypes.RelationshipIndirect
		if pkg.isRoot() {
			relationship = ftypes.RelationshipRoot
		} else if directDeps.Contains(pkg.Name) {
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
