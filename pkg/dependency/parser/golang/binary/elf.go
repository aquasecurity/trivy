package binary

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"io"
	"sort"
	"strings"

	"golang.org/x/xerrors"

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

	syms, err := strSymbols(f)
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
		if sym.Size == 0 {
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

// strSymbols returns the symbols of the symbol table of f whose names end in
// ".str", as f.Symbols decodes them. It reads the string table, then the
// symbol table only if the string table holds such a name, both as streams.
// f.Symbols holds both tables and allocates every symbol and its name, which
// for the largest Go binaries takes hundreds of megabytes.
func strSymbols(f *elf.File) ([]elf.Symbol, error) {
	symtab := f.SectionByType(elf.SHT_SYMTAB)
	if symtab == nil || symtab.Size == 0 {
		return nil, elf.ErrNoSymbols
	}
	var size uint64
	switch f.Class {
	case elf.ELFCLASS32:
		size = elf.Sym32Size
	case elf.ELFCLASS64:
		size = elf.Sym64Size
	default:
		return nil, xerrors.Errorf("unknown ELF class %v", f.Class)
	}
	if symtab.Size%size != 0 {
		return nil, xerrors.New("length of symbol section is not a multiple of the symbol size")
	}
	if symtab.Link == 0 || int(symtab.Link) >= len(f.Sections) {
		return nil, xerrors.New("section has invalid string table link")
	}

	names, err := readStrNames(f.Sections[symtab.Link].Open())
	if err != nil {
		return nil, xerrors.Errorf("cannot load string table section: %w", err)
	}
	if len(names) == 0 {
		return nil, nil
	}

	r := bufio.NewReaderSize(symtab.Open(), 64<<10)
	b := make([]byte, size)
	var syms []elf.Symbol
	for i := range symtab.Size / size {
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, xerrors.Errorf("cannot load symbol section: %w", err)
		}
		// The first entry is the null symbol.
		if i == 0 {
			continue
		}
		// Decode the entry by the layout of elf.Sym32 or elf.Sym64.
		var sym elf.Symbol
		if f.Class == elf.ELFCLASS32 {
			sym.Value = uint64(f.ByteOrder.Uint32(b[4:8]))
			sym.Size = uint64(f.ByteOrder.Uint32(b[8:12]))
			sym.Info, sym.Other = b[12], b[13]
			sym.Section = elf.SectionIndex(f.ByteOrder.Uint16(b[14:16]))
		} else {
			sym.Info, sym.Other = b[4], b[5]
			sym.Section = elf.SectionIndex(f.ByteOrder.Uint16(b[6:8]))
			sym.Value = f.ByteOrder.Uint64(b[8:16])
			sym.Size = f.ByteOrder.Uint64(b[16:24])
		}
		var ok bool
		if sym.Name, ok = names.lookup(f.ByteOrder.Uint32(b[0:4])); ok {
			syms = append(syms, sym)
		}
	}
	return syms, nil
}

// A strName is a string of an ELF string table that ends in ".str", and its
// offset in the table.
type strName struct {
	off  uint64
	name string
}

// strNames holds the strings of a string table that end in ".str", in
// increasing offset order.
type strNames []strName

// readStrNames reads an ELF string table from r and returns its strings that
// end in ".str".
func readStrNames(r io.Reader) (strNames, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var names strNames
	var off uint64
	for {
		b, err := br.ReadSlice(0)
		if errors.Is(err, bufio.ErrBufferFull) {
			// The string is longer than the buffer: gather it whole.
			long := bytes.Clone(b)
			for errors.Is(err, bufio.ErrBufferFull) {
				b, err = br.ReadSlice(0)
				long = append(long, b...)
			}
			b = long
		}
		if errors.Is(err, io.EOF) {
			// Bytes after the last NUL name nothing, as in debug/elf.
			return names, nil
		}
		if err != nil {
			return nil, err
		}
		if s := b[:len(b)-1]; bytes.HasSuffix(s, []byte(".str")) {
			names = append(names, strName{off: off, name: string(s)})
		}
		off += uint64(len(b))
	}
}

// lookup returns the name at offset off of the string table, which runs to
// the next NUL, if it ends in ".str". The name can start inside a longer
// string: linkers share the tails of the strings of a table.
func (names strNames) lookup(off uint32) (string, bool) {
	// names[i] is the last string that starts at or before off.
	i := sort.Search(len(names), func(i int) bool { return names[i].off > uint64(off) }) - 1
	if i < 0 {
		return "", false
	}
	k := uint64(off) - names[i].off
	if k >= uint64(len(names[i].name)) {
		return "", false
	}
	name := names[i].name[k:]
	if !strings.HasSuffix(name, ".str") {
		return "", false
	}
	return name, true
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
