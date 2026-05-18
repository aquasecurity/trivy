package parser

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/mapfs"
)

// newTestFS creates a temp layout simulating a real scan:
//
//	tmpDir/
//	  secret.txt              ← sensitive file OUTSIDE scan root
//	  scanroot/               ← underlyingRoot, actual scan directory
//	    userdata.sh           ← virtual file in scan root
//	    modules/vpc/
//	      userdata.sh         ← virtual file in child module
func newTestFS(t *testing.T) *mapfs.FS {
	t.Helper()
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "secret.txt"), []byte("sensitive-data"), 0o600))

	scanRoot := filepath.Join(tmpDir, "scanroot")
	require.NoError(t, os.MkdirAll(scanRoot, 0o755))

	mfs := mapfs.New(mapfs.WithUnderlyingRoot(scanRoot))
	require.NoError(t, mfs.WriteVirtualFile("userdata.sh", []byte("#!/bin/bash"), 0o644))
	require.NoError(t, mfs.MkdirAll("modules/vpc", 0o755))
	require.NoError(t, mfs.WriteVirtualFile("modules/vpc/userdata.sh", []byte("#!/bin/bash"), 0o644))
	return mfs
}

func TestFunctions_File(t *testing.T) {
	tests := []struct {
		name    string
		baseDir string
		path    string
		want    string
		wantErr string
	}{
		{name: "file in scan root", baseDir: ".", path: "userdata.sh", want: "#!/bin/bash"},
		{name: "file read from child module", baseDir: "modules/vpc", path: "userdata.sh", want: "#!/bin/bash"},
		{name: "traversal one level up", baseDir: ".", path: "../secret.txt", wantErr: "no file exists at"},
		{name: "traversal parent dir only", baseDir: ".", path: "..", wantErr: "no file exists at"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fns := Functions(newTestFS(t), tt.baseDir)
			val, err := fns["file"].Call([]cty.Value{cty.StringVal(tt.path)})
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, val.AsString())
		})
	}
}

// wrappedFS wraps fs.FS so that the *mapfs.FS type assertion in Functions() misses,
// exercising the mapfs.New() fallback path.
type wrappedFS struct{ fs.FS }

func TestFunctions_File_UnknownFSType(t *testing.T) {
	// Even though the wrapped FS contains userdata.sh, Functions() cannot
	// unwrap it, falls back to mapfs.New(), and the call must fail — not
	// silently read from the host filesystem.
	fns := Functions(wrappedFS{newTestFS(t)}, ".")
	_, err := fns["file"].Call([]cty.Value{cty.StringVal("userdata.sh")})
	assert.ErrorContains(t, err, "no file exists at")
}

func TestFunctions_FileExists(t *testing.T) {
	tests := []struct {
		name string
		path string
		want cty.Value
	}{
		{name: "file in scan root", path: "userdata.sh", want: cty.True},
		{name: "traversal one level up", path: "../secret.txt", want: cty.False},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fns := Functions(newTestFS(t), ".")
			val, err := fns["fileexists"].Call([]cty.Value{cty.StringVal(tt.path)})
			require.NoError(t, err)
			assert.Equal(t, tt.want, val)
		})
	}
}
