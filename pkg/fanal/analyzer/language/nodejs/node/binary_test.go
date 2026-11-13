package node

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Build a minimal ELF so parser coverage needs neither a compiler nor large
// architecture-specific Node executable fixtures.
func nodeELF(t *testing.T, machine elf.Machine, sectionName, contents string) []byte {
	t.Helper()
	names := []byte("\x00.shstrtab\x00" + sectionName + "\x00")
	const sectionOffset = 64
	const dataOffset = sectionOffset + 3*64
	header := elf.Header64{Type: uint16(elf.ET_EXEC), Machine: uint16(machine), Version: 1, Shoff: sectionOffset, Ehsize: 64, Shentsize: 64, Shnum: 3, Shstrndx: 1}
	copy(header.Ident[:], []byte{'\x7f', 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1})
	var out bytes.Buffer
	for _, value := range []any{header, elf.Section64{}, elf.Section64{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: dataOffset, Size: uint64(len(names))}, elf.Section64{Name: 11, Type: uint32(elf.SHT_PROGBITS), Off: uint64(dataOffset + len(names)), Size: uint64(len(contents))}} {
		require.NoError(t, binary.Write(&out, binary.LittleEndian, value))
	}
	out.Write(names)
	out.WriteString(contents)
	return out.Bytes()
}

func TestBinaryParser_Parse(t *testing.T) {
	for _, machine := range []elf.Machine{elf.EM_X86_64, elf.EM_AARCH64} {
		t.Run(machine.String(), func(t *testing.T) {
			tests := []struct{ name, contents, want string }{
				{name: "release", contents: "\x00node.js/v26.12.1\x00", want: "26.12.1"},
				{name: "prerelease", contents: "node.js/v26.0.0-rc.1\x00", want: "26.0.0-rc.1"},
				{name: "nightly", contents: "node.js/v27.0.0-nightly20261001abcdef\x00", want: "27.0.0-nightly20261001abcdef"},
				{name: "unrelated version", contents: "v26.12.1\x00"},
				{name: "unrelated product", contents: "other.js/v26.12.1\x00"},
				{name: "embedded prefix", contents: "prefix node.js/v26.12.1\x00"},
				{name: "embedded suffix", contents: "node.js/v26.12.1Protocol-Version\x00"},
				{name: "incomplete version", contents: "node.js/v26.12\x00"},
				{name: "unterminated string", contents: "node.js/v26.12.1"},
				{name: "duplicates", contents: "node.js/v26.12.1\x00node.js/v26.12.1\x00", want: "26.12.1"},
				{name: "conflicting versions", contents: "node.js/v26.12.1\x00node.js/v24.22.1\x00"},
				{name: "large preceding token", contents: strings.Repeat("x", 70000) + "\x00node.js/v26.12.1\x00", want: "26.12.1"},
				{name: "large token containing product", contents: strings.Repeat("x", 65536) + "node.js/v26.12.1\x00"},
				{name: "buffer boundary", contents: strings.Repeat("x", 65530) + "\x00node.js/v26.12.1\x00", want: "26.12.1"},
				{name: "empty section"},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					pkgs, deps, err := (binaryParser{}).Parse(t.Context(), bytes.NewReader(nodeELF(t, machine, ".rodata", tt.contents)))
					require.NoError(t, err)
					assert.Empty(t, deps)
					if tt.want == "" {
						assert.Empty(t, pkgs)
						return
					}
					assert.Equal(t, []types.Package{{ID: "node@" + tt.want, Name: "node", Version: tt.want}}, pkgs)
				})
			}
		})
	}
}

func TestBinaryParser_UnsupportedFiles(t *testing.T) {
	for _, tt := range []struct {
		name     string
		contents []byte
	}{
		{name: "not ELF", contents: []byte("node.js/v26.12.1\x00")},
		{name: "truncated ELF header", contents: []byte("\x7fELF")},
		{name: "missing rodata", contents: nodeELF(t, elf.EM_X86_64, ".data", "node.js/v26.12.1\x00")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pkgs, deps, err := (binaryParser{}).Parse(t.Context(), bytes.NewReader(tt.contents))
			require.NoError(t, err)
			assert.Empty(t, pkgs)
			assert.Empty(t, deps)
		})
	}
}

func TestBinaryParser_Canceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	pkgs, deps, err := (binaryParser{}).Parse(ctx, bytes.NewReader(nodeELF(t, elf.EM_X86_64, ".rodata", "node.js/v26.12.1\x00")))
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, pkgs)
	assert.Empty(t, deps)
}

func TestNodeAnalyzer_AnalyzeBinary(t *testing.T) {
	path := "nodejs/bin/node"
	got, err := (nodeAnalyzer{}).Analyze(t.Context(), analyzer.AnalysisInput{FilePath: path, Content: bytes.NewReader(nodeELF(t, elf.EM_AARCH64, ".rodata", "node.js/v26.12.1\x00"))})
	require.NoError(t, err)
	assert.Equal(t, &analyzer.AnalysisResult{Applications: []types.Application{{Type: types.Node, FilePath: path, Packages: types.Packages{{ID: "node@26.12.1", Name: "node", Version: "26.12.1", FilePath: path}}}}}, got)
}

func TestNodeAnalyzer_RequiredBinary(t *testing.T) {
	for _, tt := range []struct {
		name, path string
		mode       os.FileMode
		want       bool
	}{
		{name: "distroless", path: "nodejs/bin/node", mode: 0o755, want: true},
		{name: "standard", path: "usr/local/bin/node", mode: 0o755, want: true},
		{name: "nodejs", path: "usr/bin/nodejs", mode: 0o755, want: true},
		{name: "non executable", path: "nodejs/bin/node", mode: 0o644},
		{name: "unrelated executable", path: "usr/bin/not-node", mode: 0o755},
		{name: "directory", path: "node", mode: os.ModeDir | 0o755},
		{name: "symlink", path: "node", mode: os.ModeSymlink | 0o755},
	} {
		t.Run(tt.name, func(t *testing.T) {
			info, err := fs.Stat(fstest.MapFS{"node": &fstest.MapFile{Mode: tt.mode}}, "node")
			require.NoError(t, err)
			assert.Equal(t, tt.want, (nodeAnalyzer{}).Required(tt.path, info))
		})
	}
	assert.False(t, (nodeAnalyzer{}).Required("node", nil))
}

func TestBinaryParser_TruncatedSection(t *testing.T) {
	data := nodeELF(t, elf.EM_X86_64, ".rodata", "node.js/v26.12.1\x00trailing bytes")
	data = data[:len(data)-5]
	pkgs, deps, err := (binaryParser{}).Parse(t.Context(), bytes.NewReader(data))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.Empty(t, pkgs)
	assert.Empty(t, deps)
}
