package uv

import (
	"github.com/BurntSushi/toml"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Lock struct {
	Packages []Package `toml:"package"`
}

func (l Lock) packages() map[string]Package {
	return lo.SliceToMap(l.Packages, func(pkg Package) (string, Package) {
		return pkg.Name, pkg
	})
}

func (l Lock) directDeps() map[string]struct{} {
	deps := make(map[string]struct{})
	root, exists := l.root()
	if !exists {
		return deps
	}
	for _, dep := range root.Dependencies {
		deps[dep.Name] = struct{}{}
	}
	return deps
}

func (l Lock) devDeps() map[string]struct{} {
	devDeps := make(map[string]struct{})

	root, ok := l.root()
	if !ok {
		return devDeps
	}

	packages := l.packages()
	visited := make(map[string]struct{})

	var walkDeps func(Package)
	walkDeps = func(pkg Package) {
		if _, ok := visited[pkg.Name]; ok {
			return
		}
		visited[pkg.Name] = struct{}{}
		for _, dep := range pkg.Dependencies {
			depPkg, exists := packages[dep.Name]
			if !exists {
				continue
			}
			walkDeps(depPkg)
		}
	}

	walkDeps(root)

	for _, pkg := range packages {
		if _, exists := visited[pkg.Name]; !exists {
			devDeps[pkg.Name] = struct{}{}
		}
	}

	return devDeps
}

func (l Lock) root() (Package, bool) {
	for _, pkg := range l.Packages {
		if pkg.isRoot() {
			return pkg, true
		}
	}

	return Package{}, false
}

type Package struct {
	Name         string       `toml:"name"`
	Version      string       `toml:"version"`
	Source       Source       `toml:"source"`
	Dependencies []Dependency `toml:"dependencies"`
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

func New() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lock Lock
	if _, err := toml.NewDecoder(r).Decode(&lock); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode uv lock file: %w", err)
	}

	packages := lock.packages()
	directDeps := lock.directDeps()
	devDeps := lock.devDeps()

	var (
		pkgs []ftypes.Package
		deps []ftypes.Dependency
	)

	for _, pkg := range lock.Packages {
		if _, ok := devDeps[pkg.Name]; ok {
			continue
		}

		pkgID := dependency.ID(ftypes.Uv, pkg.Name, pkg.Version)
		relationship := ftypes.RelationshipIndirect
		if pkg.isRoot() {
			relationship = ftypes.RelationshipRoot
		} else if _, ok := directDeps[pkg.Name]; ok {
			relationship = ftypes.RelationshipDirect
		}

		pkgs = append(pkgs, ftypes.Package{
			ID:           pkgID,
			Name:         pkg.Name,
			Version:      pkg.Version,
			Indirect:     relationship == ftypes.RelationshipIndirect,
			Relationship: relationship,
		})

		dependsOn := make([]string, 0, len(pkg.Dependencies))

		for _, dep := range pkg.Dependencies {
			depPkg, exists := packages[dep.Name]
			if !exists {
				continue
			}
			dependsOn = append(dependsOn, dependency.ID(ftypes.Uv, dep.Name, depPkg.Version))
		}

		if len(dependsOn) > 0 {
			deps = append(deps, ftypes.Dependency{
				ID:        pkgID,
				DependsOn: dependsOn,
			})
		}
	}

	return pkgs, deps, nil
}
