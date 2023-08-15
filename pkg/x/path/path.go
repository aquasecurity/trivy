package path

import (
	"strings"

	"golang.org/x/exp/slices"
)

// Contains reports whether the path contains the subpath.
func Contains(filePath, subpath string) bool {
	ss := strings.Split(filePath, "/")
	return slices.Contains(ss, subpath)
}
