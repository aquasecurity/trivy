package bundle

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// The executables in testdata are built from testdata/testapp, a console app that references
// Ardalis.GuardClauses 4.5.0. See testdata/testapp/Dockerfile to regenerate them.
func TestParser_Parse(t *testing.T) {
	wantPkgs := []ftypes.Package{
		{
			ID:           "BundleApp/1.0.0",
			Name:         "BundleApp",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipRoot,
		},
		{
			ID:           "Ardalis.GuardClauses/4.5.0",
			Name:         "Ardalis.GuardClauses",
			Version:      "4.5.0",
			Relationship: ftypes.RelationshipDirect,
		},
	}
	wantDeps := []ftypes.Dependency{
		{
			ID:        "BundleApp/1.0.0",
			DependsOn: []string{"Ardalis.GuardClauses/4.5.0"},
		},
	}

	tests := []struct {
		name      string
		file      string
		wantPkgs  []ftypes.Package
		wantDeps  []ftypes.Dependency
		wantErrIs error
	}{
		{
			name:     "ELF",
			file:     "testdata/test.elf",
			wantPkgs: wantPkgs,
			wantDeps: wantDeps,
		},
		{
			name:     "PE",
			file:     "testdata/test.exe",
			wantPkgs: wantPkgs,
			wantDeps: wantDeps,
		},
		{
			name:     "Mach-O",
			file:     "testdata/test.macho",
			wantPkgs: wantPkgs,
			wantDeps: wantDeps,
		},
		{
			name:      "apphost that is not a bundle",
			file:      "testdata/apphost.elf",
			wantErrIs: ErrNonBundle,
		},
		{
			name:      "not an executable",
			file:      "testdata/dummy",
			wantErrIs: ErrUnrecognizedExe,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()

			gotPkgs, gotDeps, err := NewParser().Parse(t.Context(), f)
			if tt.wantErrIs != nil {
				require.ErrorIs(t, err, tt.wantErrIs)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantPkgs, gotPkgs)
			assert.Equal(t, tt.wantDeps, gotDeps)
		})
	}
}

const testDepsJSON = `{"runtimeTarget":{"name":".NETCoreApp,Version=v8.0/linux-x64"},"libraries":{"Newtonsoft.Json/13.0.3":{"type":"package"}}}`

var testDepsPkgs = []ftypes.Package{
	{
		ID:      "Newtonsoft.Json/13.0.3",
		Name:    "Newtonsoft.Json",
		Version: "13.0.3",
	},
}

type testEntry struct {
	fileType   byte
	path       string
	content    []byte
	compressed bool
}

// buildBundle appends the payload and the bundle header + manifest to apphost the way the .NET bundler does,
// and returns the file contents and the header offset.
func buildBundle(t testing.TB, apphost []byte, majorVersion uint32, entries []testEntry, headerDepsSize int64) ([]byte, int64) {
	t.Helper()
	var buf bytes.Buffer
	buf.Write(apphost)

	type placed struct {
		offset, size, compressedSize int64
	}
	locs := make([]placed, len(entries))
	for i, e := range entries {
		locs[i].offset = int64(buf.Len())
		locs[i].size = int64(len(e.content))
		if e.compressed {
			w, err := flate.NewWriter(&buf, flate.BestCompression)
			require.NoError(t, err)
			_, err = w.Write(e.content)
			require.NoError(t, err)
			require.NoError(t, w.Close())
			locs[i].compressedSize = int64(buf.Len()) - locs[i].offset
		} else {
			buf.Write(e.content)
		}
	}

	headerOffset := int64(buf.Len())
	le := func(v any) { require.NoError(t, binary.Write(&buf, binary.LittleEndian, v)) }
	str := func(s string) {
		buf.WriteByte(byte(len(s)))
		buf.WriteString(s)
	}

	le(majorVersion)
	le(uint32(0))
	le(int32(len(entries)))
	str("bundle-id")
	if majorVersion >= 2 {
		le(locs[0].offset)
		le(headerDepsSize)
		le(int64(0))
		le(int64(0))
		le(uint64(0))
	}
	for i, e := range entries {
		le(locs[i].offset)
		le(locs[i].size)
		if majorVersion >= 6 {
			le(locs[i].compressedSize)
		}
		buf.WriteByte(e.fileType)
		str(e.path)
	}
	return buf.Bytes(), headerOffset
}

func Test_readDepsJSON(t *testing.T) {
	deps := []byte(testDepsJSON)
	assembly := testEntry{fileType: 1, path: "App.dll", content: []byte("MZ-assembly")}

	tests := []struct {
		name           string
		majorVersion   uint32
		entries        []testEntry
		headerDepsSize int64
		truncate       int
		want           []byte
		wantErr        string
		wantErrIs      error
	}{
		{
			name:           "version 6",
			majorVersion:   6,
			entries:        []testEntry{{fileType: fileTypeDepsJSON, path: "App.deps.json", content: deps}, assembly},
			headerDepsSize: int64(len(deps)),
			want:           deps,
		},
		{
			name:           "version 6 with a compressed .deps.json",
			majorVersion:   6,
			entries:        []testEntry{{fileType: fileTypeDepsJSON, path: "App.deps.json", content: deps, compressed: true}, assembly},
			headerDepsSize: int64(len(deps)),
			want:           deps,
		},
		{
			name:         "version 1 has no .deps.json location in the header",
			majorVersion: 1,
			entries:      []testEntry{assembly, {fileType: fileTypeDepsJSON, path: "App.deps.json", content: deps}},
			want:         deps,
		},
		{
			name:         "no .deps.json",
			majorVersion: 6,
			entries:      []testEntry{assembly},
			wantErrIs:    ErrNonBundle,
		},
		{
			name:           "newer bundle version",
			majorVersion:   maxBundleVersion + 1,
			entries:        []testEntry{{fileType: fileTypeDepsJSON, path: "App.deps.json", content: deps}},
			headerDepsSize: int64(len(deps)),
			wantErr:        "unsupported .NET bundle version",
		},
		{
			name:           "truncated manifest",
			majorVersion:   6,
			entries:        []testEntry{{fileType: fileTypeDepsJSON, path: "App.deps.json", content: deps}},
			headerDepsSize: int64(len(deps)),
			truncate:       5,
			wantErr:        "malformed bundle manifest",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, headerOffset := buildBundle(t, []byte("apphost"), tt.majorVersion, tt.entries, tt.headerDepsSize)
			b = b[:len(b)-tt.truncate]

			got, err := readDepsJSON(bytes.NewReader(b), int64(len(b)), headerOffset)
			switch {
			case tt.wantErrIs != nil:
				require.ErrorIs(t, err, tt.wantErrIs)
			case tt.wantErr != "":
				require.ErrorContains(t, err, tt.wantErr)
			default:
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func Test_readDepsJSON_implausibleHeader(t *testing.T) {
	b := make([]byte, 64) // major version 0
	_, err := readDepsJSON(bytes.NewReader(b), int64(len(b)), 0)
	require.ErrorIs(t, err, ErrNonBundle)
}

func Test_readEntry_outOfBounds(t *testing.T) {
	b := []byte("0123456789")
	_, err := readEntry(bytes.NewReader(b), int64(len(b)), location{offset: 8, size: 4})
	require.ErrorContains(t, err, "is outside the file")
}

// buildPE returns a minimal PE file whose only section is `.data`, and the file offset of that section.
func buildPE(data []byte) ([]byte, int) {
	const peOffset, coffSize, sectionHeaderSize = 0x40, 24, 40
	dataOffset := peOffset + coffSize + sectionHeaderSize

	b := make([]byte, dataOffset, dataOffset+len(data))
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], peOffset)
	copy(b[peOffset:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[peOffset+6:], 1) // NumberOfSections
	// SizeOfOptionalHeader is 0, so the section table follows the COFF header.
	section := b[peOffset+coffSize:]
	copy(section, ".data")
	binary.LittleEndian.PutUint32(section[16:], uint32(len(data)))  // SizeOfRawData
	binary.LittleEndian.PutUint32(section[20:], uint32(dataOffset)) // PointerToRawData
	return append(b, data...), dataOffset
}

// buildELFWithoutSections returns a minimal 64-bit ELF file without section headers, whose only
// program header is a writable PT_LOAD segment holding data, and the file offset of that segment.
func buildELFWithoutSections(data []byte) ([]byte, int) {
	const ehdrSize, phdrSize = 64, 56
	dataOffset := ehdrSize + phdrSize

	b := make([]byte, dataOffset, dataOffset+len(data))
	copy(b, "\x7fELF\x02\x01\x01")                  // ELFCLASS64, ELFDATA2LSB, EV_CURRENT
	binary.LittleEndian.PutUint16(b[16:], 2)        // e_type: ET_EXEC
	binary.LittleEndian.PutUint16(b[18:], 62)       // e_machine: EM_X86_64
	binary.LittleEndian.PutUint32(b[20:], 1)        // e_version
	binary.LittleEndian.PutUint64(b[32:], ehdrSize) // e_phoff
	binary.LittleEndian.PutUint16(b[52:], ehdrSize) // e_ehsize
	binary.LittleEndian.PutUint16(b[54:], phdrSize) // e_phentsize
	binary.LittleEndian.PutUint16(b[56:], 1)        // e_phnum

	phdr := b[ehdrSize:]
	binary.LittleEndian.PutUint32(phdr[0:], 1)                  // p_type: PT_LOAD
	binary.LittleEndian.PutUint32(phdr[4:], 6)                  // p_flags: PF_R | PF_W
	binary.LittleEndian.PutUint64(phdr[8:], uint64(dataOffset)) // p_offset
	binary.LittleEndian.PutUint64(phdr[32:], uint64(len(data))) // p_filesz
	binary.LittleEndian.PutUint64(phdr[40:], uint64(len(data))) // p_memsz
	return append(b, data...), dataOffset
}

func TestParser_Parse_synthetic(t *testing.T) {
	// The apphost marker is the 8-byte bundle header offset followed by the signature.
	prefix := []byte("other static data")
	data := append(append(bytes.Clone(prefix), make([]byte, 8)...), bundleSignature...)
	markerOffset := len(prefix)

	executables := []struct {
		name  string
		build func([]byte) ([]byte, int)
	}{
		{name: "PE", build: buildPE},
		{name: "ELF without section headers", build: buildELFWithoutSections},
	}
	for _, exe := range executables {
		t.Run(exe.name+": bundle", func(t *testing.T) {
			apphost, dataOffset := exe.build(data)
			deps := []byte(testDepsJSON)
			b, headerOffset := buildBundle(t, apphost, 6, []testEntry{{fileType: fileTypeDepsJSON, path: "App.deps.json", content: deps}}, int64(len(deps)))
			binary.LittleEndian.PutUint64(b[dataOffset+markerOffset:], uint64(headerOffset))

			got, _, err := NewParser().Parse(t.Context(), bytes.NewReader(b))
			require.NoError(t, err)
			assert.Equal(t, testDepsPkgs, got)
		})

		t.Run(exe.name+": marker bytes that appear by chance", func(t *testing.T) {
			b, dataOffset := exe.build(data)
			binary.LittleEndian.PutUint64(b[dataOffset+markerOffset:], 0x40) // points into the headers
			_, _, err := NewParser().Parse(t.Context(), bytes.NewReader(b))
			require.ErrorIs(t, err, ErrNonBundle)
		})
	}
}
