package parallel_test

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/parallel"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// removedFS lists the removed file in ReadDir but fails to open it.
type removedFS struct {
	fstest.MapFS
	removed string
}

func (f removedFS) Open(name string) (fs.File, error) {
	if name == f.removed {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return f.MapFS.Open(name)
}

func TestWalkDirRemovedFile(t *testing.T) {
	fsys := removedFS{
		MapFS: fstest.MapFS{
			"a": {Data: []byte("a")},
			"b": {Data: []byte("b")},
		},
		removed: "b",
	}

	var got []string
	err := parallel.WalkDir(t.Context(), fsys, ".", 1,
		func(path string, _ fs.FileInfo, _ xio.ReadSeekerAt) (string, error) {
			return path, nil
		},
		func(path string) error {
			got = append(got, path)
			return nil
		})
	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, got)
}
