package resolvers

import (
	"context"
	"crypto/md5" // #nosec
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

type cacheResolver struct{}

var Cache = &cacheResolver{}

const tempDirName = ".aqua"

var defaultCacheDir = filepath.Join(os.TempDir(), tempDirName, "cache")

func locateCacheFS(cacheDir string) (fs.FS, error) {
	dir, err := locateCacheDir(cacheDir)
	if err != nil {
		return nil, err
	}
	return os.DirFS(dir), nil
}

func locateCacheDir(cacheDir string) (string, error) {
	if cacheDir == "" {
		cacheDir = defaultCacheDir
	}

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
	cacheFS, err := locateCacheFS(opt.CacheDir)
	if err != nil {
		opt.Debug("No cache filesystem is available on this machine.")
		return nil, "", "", false, nil
	}

	src := removeSubdirFromSource(opt.Source)
	key := cacheKey(src, opt.Version)

	opt.Debug("Trying to resolve: %s", key)
	if info, err := fs.Stat(cacheFS, filepath.ToSlash(key)); err == nil && info.IsDir() {
		opt.Debug("Module '%s' resolving via cache...", opt.Name)
		cacheDir, err := locateCacheDir(opt.CacheDir)
		if err != nil {
			return nil, "", "", true, err
		}

		return os.DirFS(filepath.Join(cacheDir, key)), opt.OriginalSource, ".", true, nil
	}
	return nil, "", "", false, nil
}

func cacheKey(source, version string) string {
	hash := md5.Sum([]byte(source + ":" + version)) // #nosec
	return hex.EncodeToString(hash[:])
}
