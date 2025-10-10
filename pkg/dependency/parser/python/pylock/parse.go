package pylock

import (
	"github.com/BurntSushi/toml"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/python"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
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
	Name   string `toml:"name"`
	Marker string `toml:"marker"`
}

// Parser parses pylock.toml defined in PEP518.
// https://peps.python.org/pep-0751
type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("pylock"),
	}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lock Pylock
	if _, err := toml.NewDecoder(r).Decode(&lock); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode pylock.toml: %w", err)
	}

	var pkgs []ftypes.Package
	var deps []ftypes.Dependency

	for _, pkg := range lock.Packages {
		pkgID := packageID(pkg.Name, pkg.Version)
		pkgs = append(pkgs, ftypes.Package{
			ID:      pkgID,
			Name:    python.NormalizePkgName(pkg.Name, true),
			Version: pkg.Version,
		})
	}
	return pkgs, deps, nil
}

func packageID(name, ver string) string {
	return dependency.ID(ftypes.PyLock, name, ver)
}
