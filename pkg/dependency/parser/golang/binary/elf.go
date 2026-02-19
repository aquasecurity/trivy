package binary

import (
	"debug/elf"
	"io"
	"strings"

	"github.com/aquasecurity/trivy/pkg/log"
)

// elfSymbolVersion attempts to extract the version from the ELF symbol table.
//
// When Go builds with `-ldflags "-X main.version=1.0.0"`, the linker creates `.str`-suffixed
// symbols (e.g. `main.version.str`) containing the string value. Trivy normally extracts
// these values by parsing the `-ldflags` recorded in the binary's buildinfo. However, when
// `-trimpath` is used, Go does not record `-ldflags` in the buildinfo due to a known bug
// (https://go.dev/issue/63432), making the existing ldflags parsing ineffective.
// The `.str` symbols in the ELF symbol table remain intact regardless of `-trimpath`,
// so reading them directly serves as a fallback.
//
// This only works for unstripped ELF binaries where `.symtab` is present.
// Binaries built with `-ldflags "-s -w"` strip the symbol table and cannot be handled here.
func (p *Parser) elfSymbolVersion(r io.ReaderAt, moduleName string) string {
	f, err := elf.NewFile(r)
	if err != nil {
		p.logger.Debug("Not an ELF binary, skipping symbol table lookup", log.Err(err))
		return ""
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		p.logger.Debug("No symbol table found (binary may be stripped)", log.Err(err))
		return ""
	}

	// foundVersions uses the same 3-tier priority as ParseLDFlags:
	//   [0]: <module_path>/cmd/**/*.version.str
	//   [1]: defaultVersionPrefixes (main, common, version, cmd)
	//   [2]: other
	var foundVersions = make([][]string, 3)
	for i := range syms {
		sym := &syms[i]
		if !strings.HasSuffix(sym.Name, ".str") || sym.Size == 0 {
			continue
		}

		// Strip ".str" suffix to get the original key (e.g. "main.version")
		key := strings.TrimSuffix(sym.Name, ".str")
		if !isVersionXKey(key) {
			continue
		}

		val := readELFSymbolString(f, sym)
		if val == "" || !isValidSemVer(val) {
			continue
		}

		classifyVersion(foundVersions, key, moduleName, val)
	}

	return p.chooseVersion(moduleName, foundVersions)
}

// readELFSymbolString reads the string value of an ELF symbol.
// The offset is computed as sym.Value (virtual address) minus the section's base address,
// following the same pattern as Go's cmd/internal/objfile/elf.go (symbolData function).
// cf. https://go.dev/src/cmd/internal/objfile/elf.go
func readELFSymbolString(f *elf.File, sym *elf.Symbol) string {
	if int(sym.Section) >= len(f.Sections) {
		return ""
	}

	sec := f.Sections[sym.Section]
	offset := sym.Value - sec.Addr
	buf := make([]byte, sym.Size)
	if _, err := sec.ReadAt(buf, int64(offset)); err != nil {
		return ""
	}

	return strings.TrimRight(string(buf), "\x00")
}
