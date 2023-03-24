package cargo

import (
	"io"
	"strings"

	"github.com/BurntSushi/toml"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"

	"golang.org/x/xerrors"
)

type cargoPkg struct {
	Name         string   `toml:"name"`
	Version      string   `toml:"version"`
	Source       string   `toml:"source,omitempty"`
	Dependencies []string `toml:"dependencies,omitempty"`
}
type Lockfile struct {
	Packages []cargoPkg `toml:"package"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockfile Lockfile
	decoder := toml.NewDecoder(r)
	if _, err := decoder.Decode(&lockfile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, nil, xerrors.Errorf("seek error: %w", err)
	}

	// naive parser to get line numbers by package from lock file
	pkgParser := naivePkgParser{r: r}
	lineNumIdx := pkgParser.parse()

	var libs []types.Library
	var deps []types.Dependency
	for _, pkg := range lockfile.Packages {
		pkgID := utils.PackageID(pkg.Name, pkg.Version)
		lib := types.Library{
			ID:      pkgID,
			Name:    pkg.Name,
			Version: pkg.Version,
		}
		if pos, ok := lineNumIdx[pkgID]; ok {
			lib.Locations = []types.Location{{StartLine: pos.start, EndLine: pos.end}}
		}

		libs = append(libs, lib)
		dep := parseDependencies(pkgID, pkg)
		if dep != nil {
			deps = append(deps, *dep)
		}
	}
	return libs, deps, nil
}
func parseDependencies(pkgId string, pkg cargoPkg) *types.Dependency {
	dependOn := []string{}
	for _, pkgDep := range pkg.Dependencies {
		/*
			Dependency entries look like:
			"unsafe-any 0.4.2 (registry+https://github.com/rust-lang/crates.io-index)"
		*/

		fields := strings.Fields(pkgDep)
		if len(fields) != 3 {
			continue
		}
		name := fields[0]
		version := fields[1]
		dependOn = append(dependOn, utils.PackageID(name, version))
	}
	if len(dependOn) > 0 {
		return &types.Dependency{
			ID:        pkgId,
			DependsOn: dependOn,
		}
	} else {
		return nil
	}
}
