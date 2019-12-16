package cache

import (
	"os"

	"golang.org/x/xerrors"
)

type Cache interface {
	Clear() error
}

type RealCache struct {
	Directory string
}

func Initialize(cacheDir string) Cache {
	return &RealCache{Directory: cacheDir}
}

func (rc RealCache) Clear() error {
	if err := os.RemoveAll(rc.Directory); err != nil {
		return xerrors.New("failed to remove cache")
	}
	return nil
}
