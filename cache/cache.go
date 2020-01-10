package cache

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"
)

const (
	cacheDirName = "fanal"
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
	directory string
}

func Initialize(cacheDir string) Cache {
	return &FSCache{directory: filepath.Join(cacheDir, cacheDirName)}
}

func (fs FSCache) Get(key string) io.Reader {
	filePath := filepath.Join(fs.directory, replacer.Replace(key))
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	return f
}

func (fs FSCache) Set(key string, file io.Reader) (io.Reader, error) {
	filePath := filepath.Join(fs.directory, replacer.Replace(key))
	if err := os.MkdirAll(fs.directory, os.ModePerm); err != nil {
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
	if err := os.RemoveAll(fs.directory); err != nil {
		return xerrors.New("failed to remove cache")
	}
	return nil
}
