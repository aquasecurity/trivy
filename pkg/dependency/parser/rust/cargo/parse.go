package cargo

import (
	"io"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
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

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("cargo"),
	}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
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
	pkgMap := lo.SliceToMap(lockfile.Packages, func(pkg cargoPkg) (string, cargoPkg) {
		return pkg.Name, pkg
	})

	var pkgs ftypes.Packages
	var deps ftypes.Dependencies
	for _, lpkg := range lockfile.Packages {
		pkgID := packageID(lpkg.Name, lpkg.Version)
		pkg := ftypes.Package{
			ID:      pkgID,
			Name:    lpkg.Name,
			Version: lpkg.Version,
		}
		if pos, ok := lineNumIdx[pkgID]; ok {
			pkg.Locations = []ftypes.Location{
				{
					StartLine: pos.start,
					EndLine:   pos.end,
				},
			}
		}

		pkgs = append(pkgs, pkg)
		dep := p.parseDependencies(pkgID, lpkg, pkgMap)
		if dep != nil {
			deps = append(deps, *dep)
		}
	}
	sort.Sort(pkgs)
	sort.Sort(deps)
	return pkgs, deps, nil
}
func (p *Parser) parseDependencies(pkgId string, pkg cargoPkg, pkgs map[string]cargoPkg) *ftypes.Dependency {
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
				p.logger.Debug("Cannot find version", log.String("name", name))
				continue
			}
			dependOn = append(dependOn, packageID(name, version.Version))
		// 2: non-unique dependency in new lock file
		// 3: old lock file
		case 2, 3:
			dependOn = append(dependOn, packageID(fields[0], fields[1]))
		default:
			p.logger.Debug("Wrong dependency format", log.String("dep", pkgDep))
			continue
		}
	}
	if len(dependOn) > 0 {
		sort.Strings(dependOn)
		return &ftypes.Dependency{
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
