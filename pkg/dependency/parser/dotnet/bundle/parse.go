package bundle

import (
	"bytes"
	"compress/flate"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"io"
	"slices"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	core "github.com/aquasecurity/trivy/pkg/dependency/parser/dotnet/core_deps"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var (
	ErrUnrecognizedExe = xerrors.New("unrecognized executable format")
	ErrNonBundle       = xerrors.New("not a .NET single-file bundle")
)

// bundleSignature is the SHA-256 hash of ".net core bundle". The apphost of a single-file bundle
// stores the offset of the bundle header in the 8 bytes right before it.
// It is decoded at run time so that Trivy's own executable does not contain the marker bytes.
// cf. https://github.com/dotnet/runtime/blob/main/src/native/corehost/apphost/bundle_marker.c
var bundleSignature = lo.Must(hex.DecodeString("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae"))

const (
	// fileTypeDepsJSON is the manifest entry type of the embedded .deps.json.
	// cf. https://github.com/dotnet/runtime/blob/main/src/installer/managed/Microsoft.NET.HostModel/Bundle/FileType.cs
	fileTypeDepsJSON = 3

	// maxBundleVersion is the latest bundle format version this parser understands (.NET 6+).
	maxBundleVersion = 6

	// Upper bounds that keep a malformed file from causing large allocations.
	maxDataSectionSize = 64 << 20
	maxManifestSize    = 16 << 20
	maxDepsJSONSize    = 32 << 20
	maxManifestEntries = 1 << 16
	maxStringLength    = 1 << 14
)

// Parser reads the .deps.json that `dotnet publish -p:PublishSingleFile=true` embeds in the
// executable, and parses it with the regular .deps.json parser.
type Parser struct {
	depsParser *core.Parser
}

func NewParser() *Parser {
	return &Parser{
		depsParser: core.NewParser(),
	}
}

func (p *Parser) Parse(ctx context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	size, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, nil, xerrors.Errorf("seek error: %w", err)
	}

	headerOffset, err := findHeaderOffset(r, size)
	if err != nil {
		return nil, nil, err
	}

	depsJSON, err := readDepsJSON(r, size, headerOffset)
	if err != nil {
		return nil, nil, err
	}

	pkgs, deps, err := p.depsParser.Parse(ctx, bytes.NewReader(depsJSON))
	if err != nil {
		return nil, nil, xerrors.Errorf("embedded .deps.json parse error: %w", err)
	}

	// Line numbers refer to the embedded .deps.json, not to the executable.
	for i := range pkgs {
		pkgs[i].Locations = nil
	}
	return pkgs, deps, nil
}

// findHeaderOffset returns the offset of the bundle header recorded in the apphost.
// Only the `.data` section, where the apphost keeps the marker as a static initialized array,
// is read, so other executables are rejected cheaply.
func findHeaderOffset(r io.ReaderAt, fileSize int64) (int64, error) {
	data, err := dataSection(r, fileSize)
	if err != nil {
		return 0, err
	}

	i := bytes.Index(data, bundleSignature)
	if i < 8 {
		return 0, ErrNonBundle
	}

	// The offset is zero for an apphost that is not a single-file bundle.
	offset := int64(binary.LittleEndian.Uint64(data[i-8 : i]))
	if offset <= 0 {
		return 0, ErrNonBundle
	}
	return offset, nil
}

// readRange reads size bytes at offset, checking the range against the file size before allocating.
func readRange(r io.ReaderAt, fileSize, offset, size, limit int64) ([]byte, error) {
	if offset < 0 || size <= 0 || size > limit || size > fileSize-offset {
		return nil, ErrNonBundle
	}
	b := make([]byte, size)
	if _, err := r.ReadAt(b, offset); err != nil {
		return nil, ErrNonBundle
	}
	return b, nil
}

func dataSection(r io.ReaderAt, fileSize int64) ([]byte, error) {
	magic := make([]byte, 4)
	if _, err := r.ReadAt(magic, 0); err != nil {
		return nil, ErrUnrecognizedExe
	}

	switch {
	case bytes.Equal(magic, []byte(elf.ELFMAG)):
		return elfDataSection(r, fileSize)
	case bytes.HasPrefix(magic, []byte("MZ")):
		return peDataSection(r, fileSize)
	case bytes.Equal(magic, machOMagic64):
		return machODataSection(r, fileSize)
	default:
		return nil, ErrUnrecognizedExe
	}
}

func elfDataSection(r io.ReaderAt, fileSize int64) ([]byte, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, ErrUnrecognizedExe
	}
	if s := f.Section(".data"); s != nil {
		if s.Type == elf.SHT_NOBITS || s.Size > maxDataSectionSize {
			return nil, ErrNonBundle
		}
		return readRange(r, fileSize, int64(s.Offset), int64(s.Size), maxDataSectionSize)
	}

	// Section headers are optional and can be stripped (e.g. by sstrip).
	// The initialized data is then found in the writable loadable segments.
	var data []byte
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_W == 0 || p.Filesz == 0 {
			continue
		}
		if p.Off > uint64(fileSize) || p.Filesz > maxDataSectionSize {
			return nil, ErrNonBundle
		}
		b, err := readRange(r, fileSize, int64(p.Off), int64(p.Filesz), maxDataSectionSize-int64(len(data)))
		if err != nil {
			return nil, err
		}
		data = append(data, b...)
	}
	if len(data) == 0 {
		return nil, ErrNonBundle
	}
	return data, nil
}

// peDataSection reads the `.data` section from the PE section table.
// It does not use debug/pe, which also loads the COFF symbol table and is slow for large executables.
// cf. https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
func peDataSection(r io.ReaderAt, fileSize int64) ([]byte, error) {
	const (
		dosHeaderLfanew   = 0x3c
		coffHeaderSize    = 24 // PE signature + COFF file header
		sectionHeaderSize = 40
		maxSections       = 96 // the PE format allows at most 96 sections
	)

	var lfanew [4]byte
	if _, err := r.ReadAt(lfanew[:], dosHeaderLfanew); err != nil {
		return nil, ErrUnrecognizedExe
	}
	peOffset := int64(binary.LittleEndian.Uint32(lfanew[:]))

	var hdr [coffHeaderSize]byte
	if _, err := r.ReadAt(hdr[:], peOffset); err != nil || !bytes.Equal(hdr[:4], []byte("PE\x00\x00")) {
		return nil, ErrUnrecognizedExe
	}
	numSections := int64(binary.LittleEndian.Uint16(hdr[6:8]))
	optHeaderSize := int64(binary.LittleEndian.Uint16(hdr[20:22]))
	if numSections == 0 || numSections > maxSections {
		return nil, ErrUnrecognizedExe
	}

	sections, err := readRange(r, fileSize, peOffset+coffHeaderSize+optHeaderSize, numSections*sectionHeaderSize, maxSections*sectionHeaderSize)
	if err != nil {
		return nil, ErrUnrecognizedExe
	}
	for s := range slices.Chunk(sections, sectionHeaderSize) {
		if cstring(s[:8]) != ".data" {
			continue
		}
		size := int64(binary.LittleEndian.Uint32(s[16:20]))   // SizeOfRawData
		offset := int64(binary.LittleEndian.Uint32(s[20:24])) // PointerToRawData
		return readRange(r, fileSize, offset, size, maxDataSectionSize)
	}
	return nil, ErrNonBundle
}

// machOMagic64 is MH_MAGIC_64 in little-endian byte order. .NET only produces 64-bit macOS executables.
var machOMagic64 = []byte{0xcf, 0xfa, 0xed, 0xfe}

// machODataSection reads the `__DATA,__data` section from the Mach-O load commands.
// It does not use debug/macho, which also loads the symbol table.
// cf. https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h
func machODataSection(r io.ReaderAt, fileSize int64) ([]byte, error) {
	const (
		headerSize      = 32 // mach_header_64
		segmentCmdSize  = 72 // segment_command_64
		sectionSize     = 80 // section_64
		lcSegment64     = 0x19
		sectionTypeMask = 0xff
		sZeroFill       = 0x1
		maxLoadCmdsSize = 1 << 24
	)

	var hdr [headerSize]byte
	if _, err := r.ReadAt(hdr[:], 0); err != nil {
		return nil, ErrUnrecognizedExe
	}
	numCmds := binary.LittleEndian.Uint32(hdr[16:20])
	cmdsSize := int64(binary.LittleEndian.Uint32(hdr[20:24]))
	cmds, err := readRange(r, fileSize, headerSize, cmdsSize, maxLoadCmdsSize)
	if err != nil {
		return nil, ErrUnrecognizedExe
	}

	for range numCmds {
		if len(cmds) < 8 {
			return nil, ErrUnrecognizedExe
		}
		cmd := binary.LittleEndian.Uint32(cmds[0:4])
		size := binary.LittleEndian.Uint32(cmds[4:8])
		if size < 8 || int64(size) > int64(len(cmds)) {
			return nil, ErrUnrecognizedExe
		}
		lc := cmds[:size]
		cmds = cmds[size:]
		if cmd != lcSegment64 || len(lc) < segmentCmdSize || cstring(lc[8:24]) != "__DATA" {
			continue
		}

		numSects := int64(binary.LittleEndian.Uint32(lc[64:68]))
		sects := lc[segmentCmdSize:]
		if numSects*sectionSize > int64(len(sects)) {
			return nil, ErrUnrecognizedExe
		}
		for s := range slices.Chunk(sects[:numSects*sectionSize], sectionSize) {
			if cstring(s[0:16]) != "__data" {
				continue
			}
			if binary.LittleEndian.Uint32(s[64:68])&sectionTypeMask == sZeroFill {
				return nil, ErrNonBundle
			}
			size := binary.LittleEndian.Uint64(s[40:48])
			if size > maxDataSectionSize {
				return nil, ErrNonBundle
			}
			offset := int64(binary.LittleEndian.Uint32(s[48:52]))
			return readRange(r, fileSize, offset, int64(size), maxDataSectionSize)
		}
	}
	return nil, ErrNonBundle
}

// cstring returns the NUL-padded fixed-size name as a string.
func cstring(b []byte) string {
	return string(bytes.TrimRight(b, "\x00"))
}

type location struct {
	offset         int64
	size           int64
	compressedSize int64
}

// readDepsJSON reads the bundle header and manifest at headerOffset and returns the embedded .deps.json.
// cf. https://github.com/dotnet/runtime/blob/main/src/installer/managed/Microsoft.NET.HostModel/Bundle/Manifest.cs
func readDepsJSON(r io.ReaderAt, fileSize, headerOffset int64) ([]byte, error) {
	// The header and manifest are written at the end of the bundle, so they are small.
	// Anything else means the marker bytes appeared by chance in another executable.
	manifestSize := fileSize - headerOffset
	if headerOffset >= fileSize || manifestSize > maxManifestSize {
		return nil, ErrNonBundle
	}

	buf := make([]byte, manifestSize)
	if _, err := r.ReadAt(buf, headerOffset); err != nil {
		return nil, xerrors.Errorf("unable to read the bundle manifest: %w", err)
	}
	m := &manifestReader{buf: buf}

	majorVersion := m.uint32()
	minorVersion := m.uint32()
	numFiles := m.int32()
	_ = m.string() // bundle ID
	if m.err != nil || majorVersion == 0 || majorVersion > 0xff || minorVersion != 0 || numFiles <= 0 || numFiles > maxManifestEntries {
		return nil, ErrNonBundle
	}
	if majorVersion > maxBundleVersion {
		return nil, xerrors.Errorf("unsupported .NET bundle version %d", majorVersion)
	}

	var deps location
	if majorVersion >= 2 {
		deps = location{offset: m.int64(), size: m.int64()}
		_, _ = m.int64(), m.int64() // .runtimeconfig.json location
		_ = m.uint64()              // flags
	}

	// Prefer the manifest entry: it also carries the compressed size (version 6+),
	// and it is the only location in version 1 bundles.
	for range numFiles {
		entry := location{offset: m.int64(), size: m.int64()}
		if majorVersion >= 6 {
			entry.compressedSize = m.int64()
		}
		fileType := m.byte()
		_ = m.string() // relative path
		if m.err != nil {
			break
		}
		if fileType == fileTypeDepsJSON {
			deps = entry
			break
		}
	}
	if m.err != nil {
		return nil, xerrors.Errorf("malformed bundle manifest: %w", m.err)
	}

	if deps.size <= 0 {
		return nil, ErrNonBundle
	}
	return readEntry(r, fileSize, deps)
}

func readEntry(r io.ReaderAt, fileSize int64, loc location) ([]byte, error) {
	if loc.size > maxDepsJSONSize {
		return nil, xerrors.Errorf(".deps.json is too large: %d bytes", loc.size)
	}
	if loc.compressedSize < 0 {
		return nil, xerrors.Errorf("invalid compressed size of .deps.json: %d", loc.compressedSize)
	}

	stored := loc.size
	if loc.compressedSize > 0 {
		stored = loc.compressedSize
	}
	if loc.offset < 0 || stored > fileSize-loc.offset {
		return nil, xerrors.Errorf(".deps.json entry (offset %d, size %d) is outside the file", loc.offset, stored)
	}

	sr := io.NewSectionReader(r, loc.offset, stored)
	if loc.compressedSize == 0 {
		b := make([]byte, loc.size)
		if _, err := io.ReadFull(sr, b); err != nil {
			return nil, xerrors.Errorf("read error: %w", err)
		}
		return b, nil
	}

	// The SDK does not compress .deps.json today, but the format allows it: compressed entries are raw DEFLATE.
	fr := flate.NewReader(sr)
	defer fr.Close()
	b, err := io.ReadAll(io.LimitReader(fr, loc.size+1))
	if err != nil {
		return nil, xerrors.Errorf("inflate error: %w", err)
	}
	if int64(len(b)) != loc.size {
		return nil, xerrors.Errorf("inflated .deps.json is %d bytes, expected %d", len(b), loc.size)
	}
	return b, nil
}

// manifestReader decodes the little-endian fields written by .NET's BinaryWriter.
// The first error is kept and later reads return zero values.
type manifestReader struct {
	buf []byte
	pos int
	err error
}

func (m *manifestReader) next(n int) []byte {
	if m.err != nil {
		return nil
	}
	if n < 0 || n > len(m.buf)-m.pos {
		m.err = io.ErrUnexpectedEOF
		return nil
	}
	b := m.buf[m.pos : m.pos+n]
	m.pos += n
	return b
}

func (m *manifestReader) byte() byte {
	if b := m.next(1); b != nil {
		return b[0]
	}
	return 0
}

func (m *manifestReader) uint32() uint32 {
	if b := m.next(4); b != nil {
		return binary.LittleEndian.Uint32(b)
	}
	return 0
}

func (m *manifestReader) int32() int32 {
	return int32(m.uint32())
}

func (m *manifestReader) uint64() uint64 {
	if b := m.next(8); b != nil {
		return binary.LittleEndian.Uint64(b)
	}
	return 0
}

func (m *manifestReader) int64() int64 {
	return int64(m.uint64())
}

// string reads a string prefixed with its length as a 7-bit encoded integer.
func (m *manifestReader) string() string {
	var length, shift int
	for {
		b := m.byte()
		if m.err != nil {
			return ""
		}
		length |= int(b&0x7f) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
		if shift > 28 {
			m.err = xerrors.New("invalid 7-bit encoded length")
			return ""
		}
	}
	if length > maxStringLength {
		m.err = xerrors.Errorf("string is too long: %d", length)
		return ""
	}
	return string(m.next(length))
}
