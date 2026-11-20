package composer

import (
	"regexp"
	"strings"

	"golang.org/x/xerrors"
)

// modifier matches the stability a version ends with: an optional stability with its
// number, such as "-RC1" or ".beta.2", and an optional "-dev".
// It is $modifierRegex of Composer's VersionParser.
// https://github.com/composer/semver/blob/3.6.0/src/VersionParser.php#L39
const modifier = `[._-]?(?:(stable|beta|b|RC|alpha|a|patch|pl|p)((?:[.-]?\d+)*)?)?([.-]?dev)?`

var (
	// classicalRegexp matches classical versioning, such as "v1.2.3-RC1".
	classicalRegexp = regexp.MustCompile(`(?i)^v?(\d{1,5})(\.\d+)?(\.\d+)?(\.\d+)?` + modifier + `$`)

	// dateRegexp matches date and time based versioning, such as "2010-01-02".
	dateRegexp = regexp.MustCompile(`(?i)^v?(\d{4}(?:[.:-]?\d{2}){1,6}(?:[.:-]?\d{1,3}){0,2})` + modifier + `$`)

	// buildMetadataRegexp matches a version followed by build metadata, such as "1.0.0+build.1".
	buildMetadataRegexp = regexp.MustCompile(`^([^,\s+]+)\+\S+$`)

	nonDigitRegexp = regexp.MustCompile(`\D`)
)

// version is a Composer version in its normalized form, such as "1.2.3.0-RC1".
type version string

// parseVersion normalizes a version the way Composer does before it compares versions.
// It follows VersionParser::normalize of composer/semver.
// https://github.com/composer/semver/blob/3.6.0/src/VersionParser.php#L124
//
// A branch, such as "dev-main" or "2.0.x-dev", is an error: it refers to a moving state
// of the code, so it has no place among the released versions an advisory lists.
func parseVersion(ver string) (version, error) {
	ver = strings.TrimSpace(ver)

	// Build metadata takes no part in the version order.
	if m := buildMetadataRegexp.FindStringSubmatch(ver); m != nil {
		ver = m[1]
	}

	var normalized, stability, number, dev string
	if m := classicalRegexp.FindStringSubmatch(ver); m != nil {
		// A version has four numbers, and the ones left out are zero.
		normalized = m[1] + orZero(m[2]) + orZero(m[3]) + orZero(m[4])
		stability, number, dev = m[5], m[6], m[7]
	} else if m = dateRegexp.FindStringSubmatch(ver); m != nil {
		normalized = nonDigitRegexp.ReplaceAllString(m[1], ".")
		stability, number, dev = m[2], m[3], m[4]
	} else {
		return "", xerrors.Errorf("invalid version: %q", ver)
	}

	if stability != "" {
		if stability == "stable" {
			return version(normalized), nil
		}
		normalized += "-" + expandStability(stability) + strings.TrimLeft(number, ".-")
	}
	if dev != "" {
		normalized += "-dev"
	}
	return version(normalized), nil
}

func orZero(number string) string {
	if number == "" {
		return ".0"
	}
	return number
}

// expandStability returns the name Composer normalizes a stability to.
func expandStability(stability string) string {
	stability = strings.ToLower(stability)
	switch stability {
	case "a":
		return "alpha"
	case "b":
		return "beta"
	case "p", "pl":
		return "patch"
	case "rc":
		return "RC"
	}
	return stability
}

// compare compares two versions the way PHP's version_compare does, which is the function
// Composer orders normalized versions with. It returns -1, 0 or 1.
// https://github.com/php/php-src/blob/php-8.4.0/ext/standard/versioning.c#L121
//
// The versions are split into parts, and the parts are compared in pairs: two numbers by
// value, and anything else by the order of the forms, in which a number comes between
// "RC" and "patch". That is why "1.0.0-patch1" follows "1.0.0" and "1.0.0-RC1" precedes it.
func (v version) compare(other version) int {
	parts1 := strings.Split(canonicalize(string(v)), ".")
	parts2 := strings.Split(canonicalize(string(other)), ".")

	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		var result int
		switch number1, number2 := isNumber(parts1[i]), isNumber(parts2[i]); {
		case number1 && number2:
			result = compareNumbers(parts1[i], parts2[i])
		case number1:
			result = compareForms(numberForm, parts2[i])
		case number2:
			result = compareForms(parts1[i], numberForm)
		default:
			result = compareForms(parts1[i], parts2[i])
		}
		if result != 0 {
			return result
		}
	}

	// The versions are equal as far as the shorter one goes, so the part that follows
	// decides: a number makes the longer version the greater one, and anything else is
	// compared with a number, which places "1.0.0-beta" before "1.0.0".
	switch {
	case len(parts1) > len(parts2):
		if next := parts1[len(parts2)]; !isNumber(next) {
			return compareForms(next, numberForm)
		}
		return 1
	case len(parts1) < len(parts2):
		if next := parts2[len(parts1)]; !isNumber(next) {
			return compareForms(numberForm, next)
		}
		return -1
	}
	return 0
}

// canonicalize separates the parts of a version with dots: it replaces "-", "_" and "+"
// with a dot and puts a dot between a number and anything else, so that "1.0.0-RC1"
// becomes "1.0.0.RC.1".
func canonicalize(ver string) string {
	if ver == "" {
		return ""
	}

	var sb strings.Builder
	sb.WriteByte(ver[0])
	last := ver[0] // the last byte written
	for i := 1; i < len(ver); i++ {
		prev, c := ver[i-1], ver[i]
		switch {
		case c == '-' || c == '_' || c == '+':
			if last != '.' {
				sb.WriteByte('.')
				last = '.'
			}
		case (isDigit(prev) && isNonDigit(c)) || (isNonDigit(prev) && isDigit(c)):
			if last != '.' {
				sb.WriteByte('.')
			}
			sb.WriteByte(c)
			last = c
		case !isDigit(c) && !isLetter(c):
			if last != '.' {
				sb.WriteByte('.')
				last = '.'
			}
		default:
			sb.WriteByte(c)
			last = c
		}
	}
	return sb.String()
}

func isDigit(c byte) bool {
	return '0' <= c && c <= '9'
}

func isLetter(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

// isNonDigit reports whether c is neither a digit nor a dot.
func isNonDigit(c byte) bool {
	return !isDigit(c) && c != '.'
}

func isNumber(part string) bool {
	return part != "" && isDigit(part[0])
}

// compareNumbers compares two numbers of any length by value.
func compareNumbers(number1, number2 string) int {
	number1 = strings.TrimLeft(number1, "0")
	number2 = strings.TrimLeft(number2, "0")
	if len(number1) != len(number2) {
		if len(number1) < len(number2) {
			return -1
		}
		return 1
	}
	return strings.Compare(number1, number2)
}

// numberForm stands for a number in the order of the forms.
const numberForm = "#"

// forms lists the forms version_compare knows, each with its place in the order. A part
// has the form it starts with, and the first match counts, so the order of the list
// matters. A part of no known form comes before all of them.
var forms = []struct {
	name  string
	order int
}{
	{"dev", 0},
	{"alpha", 1},
	{"a", 1},
	{"beta", 2},
	{"b", 2},
	{"RC", 3},
	{"rc", 3},
	{numberForm, 4},
	{"pl", 5},
	{"p", 5},
}

func formOrder(part string) int {
	for _, form := range forms {
		if strings.HasPrefix(part, form.name) {
			return form.order
		}
	}
	return -1
}

func compareForms(part1, part2 string) int {
	order1, order2 := formOrder(part1), formOrder(part2)
	switch {
	case order1 < order2:
		return -1
	case order1 > order2:
		return 1
	}
	return 0
}
