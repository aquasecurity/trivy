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

var cacheFS fs.FS

func init() {
	dir := cacheDir()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	cacheFS = os.DirFS(dir)
}

func cacheDir() string {

	locations := []string{
		filepath.Join(os.TempDir(), ".tfsec", "cache"),
	}
	// if we're not in docker, we can cache in the local project
	if _, err := os.Stat("/.dockerenv"); err != nil {
		tfsecDir := ".tfsec"
		if stat, err := os.Stat(tfsecDir); err == nil && stat.IsDir() && isWritable(tfsecDir) {
			projectCache := filepath.Join(tfsecDir, "cache")
			locations = append([]string{
				projectCache,
			}, locations...)
		}
	}
	for _, attempt := range locations {
		if err := os.MkdirAll(attempt, 0o755); err != nil {
			continue
		}
		if isWritable(attempt) {
			return attempt
		}
	}
	return ""
}

func (r *cacheResolver) Resolve(_ context.Context, _ fs.FS, opt Options) (filesystem fs.FS, prefix string, downloadPath string, applies bool, err error) {
	if !opt.AllowCache {
		opt.Debug("Cache is disabled.")
		return nil, "", "", false, nil
	}
	if cacheFS == nil {
		opt.Debug("No cache filesystem is available on this machine.")
		return nil, "", "", false, nil
	}
	key := cacheKey(opt.Source, opt.Version)
	opt.Debug("Trying to resolve: %s", key)
	if info, err := fs.Stat(cacheFS, filepath.ToSlash(key)); err == nil && info.IsDir() {
		opt.Debug("Module '%s' resolving via cache...", opt.Name)
		return os.DirFS(filepath.Join(cacheDir(), key)), opt.OriginalSource, ".", true, nil
	}
	return nil, "", "", false, nil
}

func cacheKey(source, version string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s:%s", source, version)))) // nolint
}
