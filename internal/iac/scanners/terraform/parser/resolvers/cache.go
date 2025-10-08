package resolvers

import (
	"context"
	"crypto/md5" // #nosec
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/log"
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
		return "", errors.New("cache directory is not writable")
	}
	return cacheDir, nil
}

func (r *cacheResolver) Resolve(_ context.Context, _ fs.FS, opt Options) (filesystem fs.FS, prefix, downloadPath string, applies bool, err error) {
	if opt.SkipCache {
		opt.Logger.Debug("Module caching is disabled")
		return nil, "", "", false, nil
	}
	cacheFS, err := locateCacheFS(opt.CacheDir)
	if err != nil {
		opt.Logger.Debug("No cache filesystem is available on this machine.", log.Err(err))
		return nil, "", "", false, nil
	}

	src, subdir := splitPackageSubdirRaw(opt.Source)
	key := cacheKey(src, opt.Version)

	opt.Logger.Debug("Trying to resolve module via cache", log.String("key", key))
	if info, err := fs.Stat(cacheFS, filepath.ToSlash(key)); err == nil && info.IsDir() {
		opt.Logger.Debug("Module resolved from cache", log.String("key", key))
		cacheDir, err := locateCacheDir(opt.CacheDir)
		if err != nil {
			return nil, "", "", true, err
		}

		return os.DirFS(filepath.Join(cacheDir, key)), opt.OriginalSource, subdir, true, nil
	}
	return nil, "", "", false, nil
}

func cacheKey(source, version string) string {
	hash := md5.Sum([]byte(source + ":" + version)) // #nosec
	return hex.EncodeToString(hash[:])
}
