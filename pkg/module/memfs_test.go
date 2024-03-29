package module

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemFS(t *testing.T) {
	m := &memFS{}
	require.Nil(t, m.current)

	const path, content = "/usr/foo/bar.txt", "my-content"
	err := m.initialize(path, strings.NewReader(content))
	require.NoError(t, err)
	require.NotNil(t, m.current)

	t.Run("happy", func(t *testing.T) {
		f, err := m.Open(path)
		require.NoError(t, err)
		actual, err := io.ReadAll(f)
		require.NoError(t, err)
		require.Equal(t, content, string(actual))
	})

	t.Run("not found", func(t *testing.T) {
		_, err = m.Open(path + "tmp")
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestMemFS_NilIsDirectory(t *testing.T) {
	// Wasm module initializes before an FS has been
	// associated to this memFS. We handle nil
	// so that the guest knows that the mount will map
	// to a directory in the future.
	m := &memFS{}
	require.Nil(t, m.current)

	f, err := m.Open(".")
	require.NoError(t, err)

	t.Run("stat is dir", func(t *testing.T) {
		st, err := f.Stat()
		require.NoError(t, err)
		require.True(t, st.IsDir())
	})

	t.Run("read invalid", func(t *testing.T) {
		buf := make([]byte, 4)
		_, err = f.Read(buf)
		require.True(t, errors.Is(err, fs.ErrInvalid))
	})
}
