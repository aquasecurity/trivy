package pylock

import (
	"sort"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/python"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Pylock struct {
	Packages []Package `toml:"packages"`
}

type Package struct {
	Name           string       `toml:"name"`
	Version        string       `toml:"version"`
	RequiresPython string       `toml:"requires-python"`
	Dependencies   []Dependency `toml:"dependencies"`
}

type Dependency struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

// Parser parses pylock.toml defined in PEP 751.
// https://peps.python.org/pep-0751
type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lock Pylock
	if _, err := toml.NewDecoder(r).Decode(&lock); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode pylock.toml: %w", err)
	}

	pkgs := make(map[string]ftypes.Package)
	deps := make(map[string][]string)

	for _, pkg := range lock.Packages {
		normalizedPkgName := python.NormalizePkgName(pkg.Name, true)
		pkgID := packageID(normalizedPkgName, pkg.Version)

		pkgs[normalizedPkgName] = ftypes.Package{
			ID:      pkgID,
			Name:    normalizedPkgName,
			Version: pkg.Version,
		}

		var dependsOn []string
		for _, dep := range pkg.Dependencies {
			dependsOn = append(dependsOn, python.NormalizePkgName(dep.Name, true))
		}
		if len(dependsOn) > 0 {
			sort.Strings(dependsOn)
			deps[normalizedPkgName] = dependsOn
		}
	}

	depSlice := lo.MapToSlice(deps, func(pkgName string, dependsOn []string) ftypes.Dependency {
		parentPkg, ok := pkgs[pkgName]
		if !ok {
			return ftypes.Dependency{}
		}

		var dependsOnIDs []string
		for _, dep := range dependsOn {
			if depPkg, ok := pkgs[dep]; ok {
				dependsOnIDs = append(dependsOnIDs, depPkg.ID)
			}
		}

		return ftypes.Dependency{
			ID:        parentPkg.ID,
			DependsOn: dependsOnIDs,
		}
	})

	pkgSlice := lo.Values(pkgs)
	sort.Sort(ftypes.Packages(pkgSlice))
	sort.Sort(ftypes.Dependencies(depSlice))

	return pkgSlice, depSlice, nil
}

func packageID(name, ver string) string {
	return dependency.ID(ftypes.PyLock, name, ver)
}
