package walker

import (
	"golang.org/x/xerrors"
	"io"
	"os"
)

type cachedLayer struct {
	size      int64
	reader    io.ReadCloser
	threshold int64 //　Layers larger than this threshold are written to file without being read into memory.
	filePath  string
}

func newCachedLayer(r io.ReadCloser, size, threshold int64) *cachedLayer {
	return &cachedLayer{
		reader:    r,
		size:      size,
		threshold: threshold,
	}
}

func (cl *cachedLayer) open() (io.ReadCloser, error) {
	rc := cl.reader
	if cl.size >= cl.threshold {
		filePath, err := os.CreateTemp("", "fanal-layer-*")
		if err != nil {
			return nil, xerrors.Errorf("failed to create the temp file for layer: %w", err)
		}

		if _, err = io.Copy(filePath, cl.reader); err != nil {
			return nil, xerrors.Errorf("failed to copy layer in file: %w", err)

		}
		cl.filePath = filePath.Name()

		cl.reader.Close() // close reader to free RAM
		rc, err = os.Open(cl.filePath)
		if err != nil {
			return nil, xerrors.Errorf("failed to open the temp layer file: %w", err)
		}
	}
	return rc, nil
}

func (cl *cachedLayer) clean() error {
	return os.Remove(cl.filePath)
}
