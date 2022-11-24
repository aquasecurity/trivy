package testutil

import (
	"compress/gzip"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const max = int64(10) << 30 // 10GB

func DecompressGzip(t *testing.T, src, dst string) {
	w, err := os.Create(dst)
	require.NoError(t, err)
	defer w.Close()

	f, err := os.Open(src)
	require.NoError(t, err)
	defer f.Close()

	gr, err := gzip.NewReader(f)
	require.NoError(t, err)

	_, err = io.CopyN(w, gr, max)
	require.ErrorIs(t, err, io.EOF)
}
