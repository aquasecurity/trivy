package version

import (
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// alphanumPattern is a regular expression to match all sequences of numeric
// characters or alphanumeric characters.
var alphanumPattern = regexp.MustCompile("([a-zA-Z]+)|([0-9]+)|(~)")

// Version represents a package version.
type Version struct {
	epoch   int
	version string
	release string
}

// NewVersion returns a parsed version
func NewVersion(ver string) (version Version) {
	var err error

	// Parse epoch
	splitted := strings.SplitN(ver, ":", 2)
	if len(splitted) == 1 {
		version.epoch = 0
		ver = splitted[0]
	} else {
		// Trim left space
		epoch := strings.TrimLeftFunc(splitted[0], unicode.IsSpace)

		version.epoch, err = strconv.Atoi(epoch)
		if err != nil {
			version.epoch = 0
		}

		ver = splitted[1]
	}

	// Parse version and release
	index := strings.Index(ver, "-")
	if index >= 0 {
		version.version = ver[:index]
		version.release = ver[index+1:]

	} else {
		version.version = ver
	}

	return version
}

// Equal returns whether this version is equal with another version.
func (v1 *Version) Equal(v2 Version) bool {
	return v1.Compare(v2) == 0
}

// GreaterThan returns whether this version is greater than another version.
func (v1 *Version) GreaterThan(v2 Version) bool {
	return v1.Compare(v2) > 0
}

// LessThan returns whether this version is less than another version.
func (v1 Version) LessThan(v2 Version) bool {
	return v1.Compare(v2) < 0
}

// Compare returns an integer comparing two version.
// The result will be 0 if v1==v2, -1 if v1 < v2, and +1 if v1 > v2.
func (v1 Version) Compare(v2 Version) int {
	// Equal
	if reflect.DeepEqual(v1, v2) {
		return 0
	}

	// Compare epochs
	if v1.epoch > v2.epoch {
		return 1
	} else if v1.epoch < v2.epoch {
		return -1
	}

	// Compare version
	ret := rpmvercmp(v1.version, v2.version)
	if ret != 0 {
		return ret
	}

	//Compare release
	return rpmvercmp(v1.release, v2.release)
}

// String returns the full version string
func (v1 Version) String() string {
	version := ""
	if v1.epoch > 0 {
		version += fmt.Sprintf("%d:", v1.epoch)
	}
	version += v1.version

	if v1.release != "" {
		version += fmt.Sprintf("-%s", v1.release)

	}
	return version
}

// rpmcmpver compares two version or release strings.
// Lifted from https://github.com/cavaliercoder/go-rpm/blob/master/version.go
//
// For the original C implementation, see:
// https://github.com/rpm-software-management/rpm/blob/master/lib/rpmvercmp.c#L16
func rpmvercmp(a, b string) int {
	// shortcut for equality
	if a == b {
		return 0
	}

	// get alpha/numeric segements
	segsa := alphanumPattern.FindAllString(a, -1)
	segsb := alphanumPattern.FindAllString(b, -1)
	segs := int(math.Min(float64(len(segsa)), float64(len(segsb))))

	// compare each segment
	for i := 0; i < segs; i++ {
		a := segsa[i]
		b := segsb[i]

		// compare tildes
		if []rune(a)[0] == '~' || []rune(b)[0] == '~' {
			if []rune(a)[0] != '~' {
				return 1
			}
			if []rune(b)[0] != '~' {
				return -1
			}
		}

		if unicode.IsNumber([]rune(a)[0]) {
			// numbers are always greater than alphas
			if !unicode.IsNumber([]rune(b)[0]) {
				// a is numeric, b is alpha
				return 1
			}

			// trim leading zeros
			a = strings.TrimLeft(a, "0")
			b = strings.TrimLeft(b, "0")

			// longest string wins without further comparison
			if len(a) > len(b) {
				return 1
			} else if len(b) > len(a) {
				return -1
			}

		} else if unicode.IsNumber([]rune(b)[0]) {
			// a is alpha, b is numeric
			return -1
		}

		// string compare
		if a < b {
			return -1
		} else if a > b {
			return 1
		}
	}

	// segments were all the same but separators must have been different
	if len(segsa) == len(segsb) {
		return 0
	}

	// If there is a tilde in a segment past the min number of segments, find it.
	if len(segsa) > segs && []rune(segsa[segs])[0] == '~' {
		return -1
	} else if len(segsb) > segs && []rune(segsb[segs])[0] == '~' {
		return 1
	}

	// whoever has the most segments wins
	if len(segsa) > len(segsb) {
		return 1
	}
	return -1
}
