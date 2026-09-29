package testutil

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/tools/txtar"
)

// TxtarToFS reads a txtar file and returns it as an fs.FS.
func TxtarToFS(t *testing.T, path string) fs.FS {
	t.Helper()
	archive, err := txtar.ParseFile(path)
	require.NoError(t, err)
	fsys, err := txtar.FS(archive)
	require.NoError(t, err)
	return fsys
}
