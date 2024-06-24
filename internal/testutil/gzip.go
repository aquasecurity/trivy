package testutil

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	maxSize   = int64(10) << 30 // 10GB
	blockSize = 4096
)

func DecompressGzip(t *testing.T, src, dst string) {
	w, err := os.Create(dst)
	require.NoError(t, err)
	defer w.Close()

	f, err := os.Open(src)
	require.NoError(t, err)
	defer f.Close()

	gr, err := gzip.NewReader(f)
	require.NoError(t, err)

	_, err = io.CopyN(w, gr, maxSize)
	require.ErrorIs(t, err, io.EOF)
}

// DecompressSparseGzip decompresses a sparse gzip file for virtual machine image.
func DecompressSparseGzip(t *testing.T, src, dst string) {
	w, err := os.Create(dst)
	require.NoError(t, err)
	defer w.Close()

	f, err := os.Open(src)
	require.NoError(t, err)
	defer f.Close()

	gr, err := gzip.NewReader(f)
	require.NoError(t, err)

	buf := make([]byte, blockSize)
	var size int
	var written int64
	for {
		n, err := gr.Read(buf)
		if n == 0 && err != nil {
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}

		size += n
		err = w.Truncate(int64(size))
		require.NoError(t, err)

		if !bytes.Equal(buf[:n], make([]byte, n)) {
			wn, err := w.WriteAt(buf[:n], int64(size-n))
			if err != nil {
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
			}
			written += int64(wn)
			if written > maxSize {
				require.Fail(t, "written size exceeds max")
			}
		}
	}
}
