package python

import (
	"regexp"
	"strings"
)

var normalizePkgNameRegexp = regexp.MustCompile(`[-_.]+`)

// NormalizePkgName normalizes the package name based on pep-0503 (with the option to disable conversion to lowercase).
// cf. https://peps.python.org/pep-0503/#normalized-names:
// The name should be lowercased with all runs of the characters ., -, or _ replaced with a single - character.
func NormalizePkgName(name string, inLowerCase bool) string {
	name = normalizePkgNameRegexp.ReplaceAllString(name, "-")

	// pep-0503 requires that all packages names MUST be lowercase.
	// But there are cases where the original case should be preserved (e.g. dist-info dir names).
	if inLowerCase {
		name = strings.ToLower(name)
	}
	return name
}
