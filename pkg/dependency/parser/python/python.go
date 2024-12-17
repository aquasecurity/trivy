package python

import "strings"

// NormalizePkgName normalizes the package name based on pep-0426
func NormalizePkgName(name string) string {
	// The package names don't use `_`, `.` or upper case, but dependency names can contain them.
	// We need to normalize those names.
	// cf. https://peps.python.org/pep-0426/#name
	name = strings.ToLower(name)              // e.g. https://github.com/python-poetry/poetry/blob/c8945eb110aeda611cc6721565d7ad0c657d453a/poetry.lock#L819
	name = strings.ReplaceAll(name, "_", "-") // e.g. https://github.com/python-poetry/poetry/blob/c8945eb110aeda611cc6721565d7ad0c657d453a/poetry.lock#L50
	name = strings.ReplaceAll(name, ".", "-") // e.g. https://github.com/python-poetry/poetry/blob/c8945eb110aeda611cc6721565d7ad0c657d453a/poetry.lock#L816
	return name
}
