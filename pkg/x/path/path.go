package path

import (
	"slices"
	"strings"
)

// Contains reports whether the path contains the subpath.
func Contains(filePath, subpath string) bool {
	ss := strings.Split(filePath, "/")
	return slices.Contains(ss, subpath)
}
