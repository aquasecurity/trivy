package uv

import (
	"context"
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

func (l Lock) packages() map[string]Package {
	return lo.SliceToMap(l.Packages, func(pkg Package) (string, Package) {
		return pkg.Name, pkg
	})
}

type Manifest struct {
	Members []string `toml:"members"`
}

func prodDeps(roots []Package, packages map[string]Package) set.Set[string] {
	visited := set.New[string]()
	for _, root := range roots {
		walkPackageDeps(root, packages, visited)
	}
	return visited
}

func walkPackageDeps(pkg Package, packages map[string]Package, visited set.Set[string]) {
	if visited.Contains(pkg.Name) {
		return
	}
	visited.Append(pkg.Name)
	for depName := range pkg.nonDevDeps().Iter() {
		depPkg, exists := packages[depName]
		if !exists {
			continue
		}
		walkPackageDeps(depPkg, packages, visited)
	}
}

func (l Lock) roots() ([]Package, error) {
	var pkgs []Package
	for _, pkg := range l.Packages {
		if pkg.isRoot() {
			pkgs = append(pkgs, pkg)
		}
	}

	if len(pkgs) > 1 {
		return nil, xerrors.New("uv lockfile must contain 1 root package")
	}

	return pkgs, nil
}

func (l Lock) workspaceMembers() []Package {
	members := set.New[string](l.Manifest.Members...)
	if members.Size() == 0 {
		return nil
	}

	var pkgs []Package
	for _, pkg := range l.Packages {
		if members.Contains(pkg.Name) {
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs
}

func (l Lock) entryPackages() ([]Package, error) {
	roots, err := l.roots()
	if err != nil {
		return nil, err
	}

	entries := roots
	entries = append(entries, l.workspaceMembers()...)
	if len(entries) == 0 {
		return nil, xerrors.New("uv lockfile must contain 1 root package")
	}
	return entries, nil
}

type Package struct {
	Name                 string                  `toml:"name"`
	Version              string                  `toml:"version"`
	Source               Source                  `toml:"source"`
	Dependencies         Dependencies            `toml:"dependencies"`
	DevDependencies      map[string]Dependencies `toml:"dev-dependencies"`
	OptionalDependencies map[string]Dependencies `toml:"optional-dependencies"`
}

func (p Package) directDeps() set.Set[string] {
	deps := p.nonDevDeps()
	for _, groupDeps := range p.DevDependencies {
		deps.Append(groupDeps.toSet().Items()...)

	}
	return deps
}

func (p Package) nonDevDeps() set.Set[string] {
	deps := p.Dependencies.toSet()
	for _, groupDeps := range p.OptionalDependencies {
		deps.Append(groupDeps.toSet().Items()...)
	}
	return deps
}

type Dependencies []struct {
	Name string `toml:"name"`
}

func (d Dependencies) toSet() set.Set[string] {
	deps := set.New[string]()
	for _, dep := range d {
		deps.Append(dep.Name)
	}
	return deps
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
	Name string `toml:"name"`
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

	entryPackages, err := lock.entryPackages()
	if err != nil {
		return nil, nil, err
	}

	packages := lock.packages()
	workspaceMembers := set.New[string](lo.Map(lock.workspaceMembers(), func(pkg Package, _ int) string {
		return pkg.Name
	})...)
	directDeps := set.New[string]()
	for _, entryPkg := range entryPackages {
		directDeps.Append(entryPkg.directDeps().Items()...)
	}

	// Production dependencies are the packages reachable from the root package
	// or, for workspace lockfiles, any workspace member package.
	prodDeps := prodDeps(entryPackages, packages)

	var (
		pkgs ftypes.Packages
		deps ftypes.Dependencies
	)

	for _, pkg := range lock.Packages {
		pkgID := packageID(pkg.Name, pkg.Version)
		relationship := ftypes.RelationshipIndirect
		switch {
		case pkg.isRoot():
			relationship = ftypes.RelationshipRoot
		case workspaceMembers.Contains(pkg.Name):
			relationship = ftypes.RelationshipWorkspace
		case directDeps.Contains(pkg.Name):
			relationship = ftypes.RelationshipDirect
		}

		pkgs = append(pkgs, ftypes.Package{
			ID:           pkgID,
			Name:         pkg.Name,
			Version:      pkg.Version,
			Relationship: relationship,
			Dev:          !prodDeps.Contains(pkg.Name),
		})

		dependsOn := make([]string, 0, len(pkg.Dependencies))

		for depName := range pkg.directDeps().Iter() {
			depPkg, exists := packages[depName]
			if !exists {
				continue
			}
			dependsOn = append(dependsOn, packageID(depName, depPkg.Version))
		}

		if len(dependsOn) > 0 {
			sort.Strings(dependsOn)
			deps = append(deps, ftypes.Dependency{
				ID:        pkgID,
				DependsOn: dependsOn,
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
