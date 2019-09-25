package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

var (
	NODE_DEP_DIR     = "node_modules"
	COMPOSER_DEP_DIR = "vendor"
	PathSeparator    = fmt.Sprintf("%c", os.PathSeparator)
)

func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "fanal")
	return dir
}

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func IsCommandAvailable(name string) bool {
	if _, err := exec.LookPath(name); err != nil {
		return false
	}
	return true
}
