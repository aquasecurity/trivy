package bundle

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// The parser reads untrusted executables, so it must never panic.

func FuzzParser_Parse(f *testing.F) {
	for _, name := range []string{"test.elf", "test.exe", "test.macho", "apphost.elf", "dummy"} {
		b, err := os.ReadFile("testdata/" + name)
		require.NoError(f, err)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = NewParser().Parse(t.Context(), bytes.NewReader(b))
	})
}

func FuzzReadDepsJSON(f *testing.F) {
	deps := []byte(testDepsJSON)
	for _, majorVersion := range []uint32{1, 2, 6} {
		b, headerOffset := buildBundle(f, nil, majorVersion, []testEntry{
			{fileType: 1, path: "App.dll", content: []byte("assembly")},
			{fileType: fileTypeDepsJSON, path: "App.deps.json", content: deps, compressed: majorVersion == 6},
		}, int64(len(deps)))
		f.Add(b, headerOffset)
	}
	f.Fuzz(func(_ *testing.T, b []byte, headerOffset int64) {
		if headerOffset < 0 {
			return
		}
		_, _ = readDepsJSON(bytes.NewReader(b), int64(len(b)), headerOffset)
	})
}
