package python

import (
	"regexp"
	"strings"
)

var normalizePkgNameRegexp = regexp.MustCompile(`[-_.]+`)

// NormalizePkgName normalizes the package name based on pep-0503
// https://peps.python.org/pep-0503/#normalized-names:
// The name should be lowercased with all runs of the characters ., -, or _ replaced with a single - character.
func NormalizePkgName(name string) string {
	return strings.ToLower(normalizePkgNameRegexp.ReplaceAllString(name, "-"))
}
