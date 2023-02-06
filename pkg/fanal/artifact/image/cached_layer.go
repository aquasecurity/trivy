package image

import (
	"io"
	"os"

	"golang.org/x/xerrors"
)

const defaultLayerSizeThreshold = int64(50) << 20 // 50MB =

type cachedLayer struct {
	rc       io.ReadCloser
	filePath string
	digest   string
}

func newCachedLayer(rc io.ReadCloser, size int64, slow bool, digest string) (*cachedLayer, error) {
	if slow || size >= defaultLayerSizeThreshold {
		tmpFile, err := os.CreateTemp("", "fanal-layer-*")
		if err != nil {
			return nil, xerrors.Errorf("failed to create the temp file for layer: %w", err)
		}

		if _, err = io.Copy(tmpFile, rc); err != nil {
			return nil, xerrors.Errorf("failed to copy layer in file: %w", err)
		}

		err = rc.Close() // close previous reader to free RAM
		if err != nil {
			return nil, xerrors.Errorf("failed to close layer stream: %w", err)
		}

		filePath := tmpFile.Name()
		f, err := os.Open(filePath)
		if err != nil {
			return nil, xerrors.Errorf("failed to open the temp layer file: %w", err)
		}
		return &cachedLayer{
			rc:       f,
			filePath: filePath,
			digest:   digest,
		}, nil
	}
	return &cachedLayer{
		rc:     rc,
		digest: digest,
	}, nil
}

func (cl cachedLayer) Read(p []byte) (n int, err error) {
	return cl.rc.Read(p)
}

func (cl cachedLayer) Close() error {
	if cl.filePath != "" {
		if err := os.Remove(cl.filePath); err != nil {
			return err
		}
	}
	return cl.rc.Close()
}
