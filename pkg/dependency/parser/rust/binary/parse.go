// Detects dependencies from Rust binaries built with https://github.com/rust-secure-code/cargo-auditable
package binary

import (
	rustaudit "github.com/microsoft/go-rustaudit"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var (
	ErrUnrecognizedExe = xerrors.New("unrecognized executable format")
	ErrNonRustBinary   = xerrors.New("non Rust auditable binary")
)

// convertError detects rustaudit.ErrUnknownFileFormat and convert to
// ErrUnrecognizedExe and convert rustaudit.ErrNoRustDepInfo to ErrNonRustBinary
func convertError(err error) error {
	if err == rustaudit.ErrUnknownFileFormat {
		return ErrUnrecognizedExe
	}
	if err == rustaudit.ErrNoRustDepInfo {
		return ErrNonRustBinary
	}

	return err
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Parse scans files to try to report Rust crates and version injected into Rust binaries
// via https://github.com/rust-secure-code/cargo-auditable
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	info, err := rustaudit.GetDependencyInfo(r)
	if err != nil {
		return nil, nil, convertError(err)
	}

	var pkgs []ftypes.Package
	var deps []ftypes.Dependency
	for _, pkg := range info.Packages {
		if pkg.Kind != rustaudit.Runtime {
			continue
		}
		pkgID := packageID(pkg.Name, pkg.Version)
		pkgs = append(pkgs, ftypes.Package{
			ID:           pkgID,
			Name:         pkg.Name,
			Version:      pkg.Version,
			Relationship: lo.Ternary(pkg.Root, ftypes.RelationshipRoot, ftypes.RelationshipUnknown), // TODO: Determine the direct dependencies by checking the dependencies of the root crate
		})

		var childDeps []string
		for _, dep_idx := range pkg.Dependencies {
			dep := info.Packages[dep_idx]
			if dep.Kind == rustaudit.Runtime {
				childDeps = append(childDeps, packageID(dep.Name, dep.Version))
			}
		}
		if len(childDeps) > 0 {
			deps = append(deps, ftypes.Dependency{
				ID:        pkgID,
				DependsOn: childDeps,
			})
		}
	}

	return pkgs, deps, nil
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.RustBinary, name, version)
}
