// Detects dependencies from Rust binaries built with https://github.com/rust-secure-code/cargo-auditable
package binary

import (
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	rustaudit "github.com/microsoft/go-rustaudit"
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

func NewParser() types.Parser {
	return &Parser{}
}

// Parse scans files to try to report Rust crates and version injected into Rust binaries
// via https://github.com/rust-secure-code/cargo-auditable
func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	info, err := rustaudit.GetDependencyInfo(r)
	if err != nil {
		return nil, nil, convertError(err)
	}

	var libs []types.Library
	for _, dep := range info.Packages {
		if dep.Kind == rustaudit.Runtime {
			libs = append(libs, types.Library{
				Name:    dep.Name,
				Version: dep.Version,
			})
		}
	}

	return libs, nil, nil
}
