package resolvers

import (
	"context"
	"crypto/md5" // nolint
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

type cacheResolver struct{}

var Cache = &cacheResolver{}

const tempDirName = ".aqua"

func locateCacheFS() (fs.FS, error) {
	dir, err := locateCacheDir()
	if err != nil {
		return nil, err
	}
	return os.DirFS(dir), nil
}

func locateCacheDir() (string, error) {
	cacheDir := filepath.Join(os.TempDir(), tempDirName, "cache")
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		return "", err
	}
	if !isWritable(cacheDir) {
		return "", fmt.Errorf("cache directory is not writable")
	}
	return cacheDir, nil
}

func (r *cacheResolver) Resolve(_ context.Context, _ fs.FS, opt Options) (filesystem fs.FS, prefix, downloadPath string, applies bool, err error) {
	if opt.SkipCache {
		opt.Debug("Cache is disabled.")
		return nil, "", "", false, nil
	}
	cacheFS, err := locateCacheFS()
	if err != nil {
		opt.Debug("No cache filesystem is available on this machine.")
		return nil, "", "", false, nil
	}
	key := cacheKey(opt.Source, opt.Version, opt.RelativePath)
	opt.Debug("Trying to resolve: %s", key)
	if info, err := fs.Stat(cacheFS, filepath.ToSlash(key)); err == nil && info.IsDir() {
		opt.Debug("Module '%s' resolving via cache...", opt.Name)
		cacheDir, err := locateCacheDir()
		if err != nil {
			return nil, "", "", true, err
		}
		return os.DirFS(filepath.Join(cacheDir, key)), opt.OriginalSource, ".", true, nil
	}
	return nil, "", "", false, nil
}

func cacheKey(source, version, relativePath string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", source, version, relativePath)))) // nolint
}
