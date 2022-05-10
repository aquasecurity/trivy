package memoryfs

import (
	"path/filepath"
	"strings"
)

func cleanse(path string) string {
	path = strings.ReplaceAll(path, "/", separator)
	path = filepath.Clean(path)
	path = strings.TrimPrefix(path, ".")
	path = strings.TrimPrefix(path, separator)
	return path
}
