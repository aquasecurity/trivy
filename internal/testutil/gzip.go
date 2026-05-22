package testutil

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
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

// FSToTar creates an in-memory tar archive from an fs.FS.
// prefix is prepended to every file path inside the archive.
func FSToTar(t *testing.T, fsys fs.FS, prefix string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, writeFSToTar(tw, fsys, prefix))
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

// FSToTarGz creates an in-memory tar.gz archive from an fs.FS.
// prefix is prepended to every file path inside the archive.
func FSToTarGz(t *testing.T, fsys fs.FS, prefix string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	require.NoError(t, writeFSToTar(tw, fsys, prefix))
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

func writeFSToTar(tw *tar.Writer, fsys fs.FS, prefix string) error {
	return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		name := path
		if prefix != "" {
			name = prefix + "/" + path
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Typeflag: tar.TypeReg, Size: int64(len(data)), Mode: 0o644,
		}); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
}
