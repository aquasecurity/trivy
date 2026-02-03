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
	Name         string       `toml:"name"`
	Version      string       `toml:"version"`
	Dependencies []Dependency `toml:"dependencies"`
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

		pkgs[pkgID] = ftypes.Package{
			ID:      pkgID,
			Name:    normalizedPkgName,
			Version: pkg.Version,
		}

		var dependsOn []string
		for _, dep := range pkg.Dependencies {
			depName := python.NormalizePkgName(dep.Name, true)
			depID := packageID(depName, dep.Version)
			dependsOn = append(dependsOn, depID)
		}
		if len(dependsOn) > 0 {
			sort.Strings(dependsOn)
			deps[pkgID] = dependsOn
		}
	}

	depSlice := lo.MapToSlice(deps, func(pkgID string, dependsOn []string) ftypes.Dependency {
		if _, ok := pkgs[pkgID]; !ok {
			return ftypes.Dependency{}
		}

		// Filter out dependencies that are not in the package list
		var dependsOnIDs []string
		for _, depID := range dependsOn {
			if _, ok := pkgs[depID]; ok {
				dependsOnIDs = append(dependsOnIDs, depID)
			}
		}

		return ftypes.Dependency{
			ID:        pkgID,
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
