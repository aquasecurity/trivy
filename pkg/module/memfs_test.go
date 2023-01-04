package module

import (
	"io"
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
