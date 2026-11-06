package binary

import (
	"debug/elf"
	"io"
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

var ParseStdlibVersion = parseStdlibVersion

// StrSymbols exports strSymbols for testing.
func StrSymbols(f *elf.File) ([]elf.Symbol, error) {
	return strSymbols(f)
}

// LookupStrName reads an ELF string table from r and looks up the name at
// offset off, as strSymbols does for each symbol.
func LookupStrName(r io.Reader, off uint32) (string, bool, error) {
	names, err := readStrNames(r)
	if err != nil {
		return "", false, err
	}
	name, ok := names.lookup(off)
	return name, ok, nil
}
