package cargo

import (
	"io"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
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

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
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

	// We need to get version for unique dependencies for lockfile v3 from lockfile.Packages
	pkgs := lo.SliceToMap(lockfile.Packages, func(pkg cargoPkg) (string, cargoPkg) {
		return pkg.Name, pkg
	})

	var libs []types.Library
	var deps []types.Dependency
	for _, pkg := range lockfile.Packages {
		pkgID := packageID(pkg.Name, pkg.Version)
		lib := types.Library{
			ID:      pkgID,
			Name:    pkg.Name,
			Version: pkg.Version,
		}
		if pos, ok := lineNumIdx[pkgID]; ok {
			lib.Locations = []types.Location{
				{
					StartLine: pos.start,
					EndLine:   pos.end,
				},
			}
		}

		libs = append(libs, lib)
		dep := parseDependencies(pkgID, pkg, pkgs)
		if dep != nil {
			deps = append(deps, *dep)
		}
	}
	sort.Sort(types.Libraries(libs))
	sort.Sort(types.Dependencies(deps))
	return libs, deps, nil
}
func parseDependencies(pkgId string, pkg cargoPkg, pkgs map[string]cargoPkg) *types.Dependency {
	var dependOn []string

	for _, pkgDep := range pkg.Dependencies {
		/*
			Dependency entries look like:
			old Cargo.lock - https://github.com/rust-lang/cargo/blob/46bac2dc448ab12fe0f182bee8d35cc804d9a6af/tests/testsuite/lockfile_compat.rs#L48-L50
				"unsafe-any 0.4.2 (registry+https://github.com/rust-lang/crates.io-index)"
			new Cargo.lock -https://github.com/rust-lang/cargo/blob/46bac2dc448ab12fe0f182bee8d35cc804d9a6af/tests/testsuite/lockfile_compat.rs#L39-L41
				"unsafe-any" - if lock file contains only 1 version of dependency
				"unsafe-any 0.4.2" if lock file contains more than 1 version of dependency
		*/
		fields := strings.Fields(pkgDep)
		switch len(fields) {
		// unique dependency in new lock file
		case 1:
			name := fields[0]
			version, ok := pkgs[name]
			if !ok {
				log.Logger.Debugf("can't find version for %s", name)
				continue
			}
			dependOn = append(dependOn, packageID(name, version.Version))
		// 2: non-unique dependency in new lock file
		// 3: old lock file
		case 2, 3:
			dependOn = append(dependOn, packageID(fields[0], fields[1]))
		default:
			log.Logger.Debugf("wrong dependency format for %s", pkgDep)
			continue
		}
	}
	if len(dependOn) > 0 {
		sort.Strings(dependOn)
		return &types.Dependency{
			ID:        pkgId,
			DependsOn: dependOn,
		}
	} else {
		return nil
	}
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Cargo, name, version)
}
