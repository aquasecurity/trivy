package cache

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
)

func init() {
	d, err := os.UserCacheDir()
	if err != nil {
		d = os.TempDir()
	}
	cacheDir = filepath.Join(d, "fanal")
	os.MkdirAll(cacheDir, os.ModePerm)
}

var (
	cacheDir string
)

func Get(key string) io.Reader {
	filePath := filepath.Join(cacheDir, key)
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	return f
}

func Set(key string, file io.Reader) (io.Reader, error) {
	filePath := filepath.Join(cacheDir, key)
	cacheFile, err := os.Create(filePath)
	if err != nil {
		return file, xerrors.Errorf("failed to create cache file: %w", err)
	}

	tee := io.TeeReader(file, cacheFile)
	return tee, nil
}
