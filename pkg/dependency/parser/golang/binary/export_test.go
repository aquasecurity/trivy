package binary

import (
	"io"
	"strings"
)

// Bridge to expose binary parser internals to tests in the binary_test package.

// ChooseMainVersion exports chooseMainVersion for testing.
func (p *Parser) ChooseMainVersion(version, ldflagsVersion, elfVersion string) string {
	return p.chooseMainVersion(version, ldflagsVersion, elfVersion)
}

// ELFSymbolVersion exports elfSymbolVersion for testing.
func (p *Parser) ELFSymbolVersion(r io.ReaderAt, name string) string {
	return p.elfSymbolVersion(r, name)
}

// StripGoExperiment strips the GOEXPERIMENT suffix from a raw GoVersion string
// (with the leading "go" prefix already removed) and returns the clean version.
// It handles both formats:
//
//	Go <=1.25: "1.25.3 X:boringcrypto" -> "1.25.3"
//	Go >=1.26: "1.26.0-X:nodwarf5"     -> "1.26.0"
func StripGoExperiment(v string) string {
	v, _, _ = strings.Cut(v, " ")
	v, _, _ = strings.Cut(v, "-X:")
	return v
}
