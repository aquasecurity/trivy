package cache

import (
	"os"
	"path/filepath"
)

var cacheDir string

// defaultDir returns/creates the cache-dir to be used for trivy operations
func defaultDir() string {
	tmpDir, err := os.UserCacheDir()
	if err != nil {
		tmpDir = os.TempDir()
	}
	return filepath.Join(tmpDir, "trivy")
}

// Dir returns the directory used for caching
func Dir() string {
	if cacheDir == "" {
		return defaultDir()
	}
	return cacheDir
}

// SetDir sets the trivy cache dir
func SetDir(dir string) {
	cacheDir = dir
}
