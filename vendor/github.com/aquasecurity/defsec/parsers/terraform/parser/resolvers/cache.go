package resolvers

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const cacheRecordFile = ".tfsec-cache"

type cacheResolver struct{}

var Cache = &cacheResolver{}

func (r *cacheResolver) Resolve(_ context.Context, opt Options) (downloadPath string, applies bool, err error) {
	if !r.isCached(opt) {
		return "", false, nil
	}
	opt.Debug("Module '%s' resolving via cache...", opt.Name)
	return getCacheDir(opt.WorkingDir, opt.Name), true, nil
}

func getCacheDir(cwd string, name string) string {
	return filepath.Join(cwd, ".tfsec", "downloaded-modules", name)
}

func (r *cacheResolver) isCached(options Options) bool {
	target := getCacheDir(options.WorkingDir, options.Name)
	info, err := os.Stat(target)
	if err != nil {
		return false
	}
	if !info.IsDir() {
		return false
	}
	// check source and version have not changed
	return verifyCacheRecord(target, options.Source, options.Version)
}

func buildCacheRecord(source, version string) string {
	if version == "" {
		return source
	}
	return fmt.Sprintf("%s:%s", source, strings.ReplaceAll(version, " ", "_"))
}

func writeCacheRecord(dir, source, version string) error {
	record := buildCacheRecord(source, version)
	return ioutil.WriteFile(filepath.Join(dir, cacheRecordFile), []byte(record), 0600)
}

func verifyCacheRecord(dir, source, version string) bool {
	expectedRecord := buildCacheRecord(source, version)
	data, err := ioutil.ReadFile(filepath.Join(dir, cacheRecordFile))
	if err != nil {
		return false
	}
	return expectedRecord == string(data)
}
