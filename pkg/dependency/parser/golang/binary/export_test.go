package binary

import "io"

// Bridge to expose binary parser internals to tests in the binary_test package.

// ChooseMainVersion exports chooseMainVersion for testing.
func (p *Parser) ChooseMainVersion(version, ldflagsVersion, elfVersion string) string {
	return p.chooseMainVersion(version, ldflagsVersion, elfVersion)
}

// ELFSymbolVersion exports elfSymbolVersion for testing.
func (p *Parser) ELFSymbolVersion(r io.ReaderAt, name string) string {
	return p.elfSymbolVersion(r, name)
}
