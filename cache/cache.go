package cache

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"
)

var (
	replacer = strings.NewReplacer("/", "_")
)

type Cache interface {
	Get(key string) io.Reader
	Set(key string, file io.Reader) (io.Reader, error)
	Clear() error
}

type FSCache struct {
	Directory string
}

func Initialize(cacheDir string) Cache {
	return &FSCache{Directory: cacheDir}
}

func (fs FSCache) Get(key string) io.Reader {
	filePath := filepath.Join(fs.Directory, replacer.Replace(key))
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	return f
}

func (fs FSCache) Set(key string, file io.Reader) (io.Reader, error) {
	filePath := filepath.Join(fs.Directory, replacer.Replace(key))
	if err := os.MkdirAll(fs.Directory, os.ModePerm); err != nil {
		return nil, xerrors.Errorf("failed to mkdir all: %w", err)
	}
	cacheFile, err := os.Create(filePath)
	if err != nil {
		return file, xerrors.Errorf("failed to create cache file: %w", err)
	}

	tee := io.TeeReader(file, cacheFile)
	return tee, nil
}

func (fs FSCache) Clear() error {
	if err := os.RemoveAll(fs.Directory); err != nil {
		return xerrors.New("failed to remove cache")
	}
	return nil
}
