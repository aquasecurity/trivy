package version

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type defaultNumSlice []int

// get function returns 0, if the slice does not have the specified index.
func (n defaultNumSlice) get(i int) int {
	if len(n) > i {
		return n[i]
	}
	return 0
}

type defaultStringSlice []string

// get function returns "", if the slice does not have the specified index.
func (s defaultStringSlice) get(i int) string {
	if len(s) > i {
		return s[i]
	}
	return ""
}

// Version represents a package version (http://man.he.net/man5/deb-version).
type Version struct {
	epoch           int
	upstreamVersion string
	debianRevision  string
}

var (
	digitRegexp    = regexp.MustCompile(`[0-9]+`)
	nonDigitRegexp = regexp.MustCompile(`[^0-9]+`)
)

// NewVersion returns a parsed version
func NewVersion(ver string) (version Version, err error) {
	// Trim space
	ver = strings.TrimSpace(ver)

	// Parse epoch
	splitted := strings.SplitN(ver, ":", 2)
	if len(splitted) == 1 {
		version.epoch = 0
		ver = splitted[0]
	} else {
		version.epoch, err = strconv.Atoi(splitted[0])
		if err != nil {
			return Version{}, fmt.Errorf("epoch parse error: %v", err)
		}

		if version.epoch < 0 {
			return Version{}, errors.New("epoch is negative")
		}
		ver = splitted[1]
	}

	// Parse upstream_version and debian_revision
	index := strings.LastIndex(ver, "-")
	if index >= 0 {
		version.upstreamVersion = ver[:index]
		version.debianRevision = ver[index+1:]

	} else {
		version.upstreamVersion = ver
	}

	// Verify upstream_version is valid
	err = verifyUpstreamVersion(version.upstreamVersion)
	if err != nil {
		return Version{}, err
	}

	// Verify debian_revision is valid
	err = verifyDebianRevision(version.debianRevision)
	if err != nil {
		return Version{}, err
	}

	return version, nil
}

func verifyUpstreamVersion(str string) error {
	if len(str) == 0 {
		return errors.New("upstream_version is empty")
	}

	// The upstream-version should start with a digit
	if !unicode.IsDigit(rune(str[0])) {
		return errors.New("upstream_version must start with digit")
	}

	// The upstream-version may contain only alphanumerics("A-Za-z0-9") and the characters .+-:~
	allowedSymbols := ".-+~:_"
	for _, s := range str {
		if !unicode.IsDigit(s) && !unicode.IsLetter(s) && !strings.ContainsRune(allowedSymbols, s) {
			return errors.New("upstream_version includes invalid character")
		}
	}
	return nil
}

func verifyDebianRevision(str string) error {
	// The debian-revision may contain only alphanumerics and the characters +.~
	allowedSymbols := "+.~_"
	for _, s := range str {
		if !unicode.IsDigit(s) && !unicode.IsLetter(s) && !strings.ContainsRune(allowedSymbols, s) {
			return errors.New("debian_revision includes invalid character")
		}
	}
	return nil
}

// Valid validates the version
func Valid(ver string) bool {
	_, err := NewVersion(ver)
	return err == nil
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

// Compare returns an integer comparing two version according to deb-version.
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
	ret := compare(v1.upstreamVersion, v2.upstreamVersion)
	if ret != 0 {
		return ret
	}

	//Compare debian_revision
	return compare(v1.debianRevision, v2.debianRevision)
}

// String returns the full version string
func (v1 Version) String() string {
	version := ""
	if v1.epoch > 0 {
		version += fmt.Sprintf("%d:", v1.epoch)
	}
	version += v1.upstreamVersion

	if v1.debianRevision != "" {
		version += fmt.Sprintf("-%s", v1.debianRevision)

	}
	return version
}

func compare(v1, v2 string) int {
	// Equal
	if v1 == v2 {
		return 0
	}

	// Extract digit strings and non-digit strings
	numbers1, strings1 := extract(v1)
	numbers2, strings2 := extract(v2)

	if len(v1) > 0 && unicode.IsDigit(rune(v1[0])) {
		strings1 = append([]string{""}, strings1...)
	}
	if len(v2) > 0 && unicode.IsDigit(rune(v2[0])) {
		strings2 = append([]string{""}, strings2...)
	}

	for i := 0; ; i++ {
		// Compare non-digit strings
		diff := compareString(strings1.get(i), strings2.get(i))
		if diff != 0 {
			return diff
		}

		// Compare digit strings
		diff = numbers1.get(i) - numbers2.get(i)
		if diff != 0 {
			return diff
		}
	}
}

func compareString(s1, s2 string) int {
	if s1 == s2 {
		return 0
	}

	for i := 0; ; i++ {
		a := 0
		if i < len(s1) {
			a = order(rune(s1[i]))
		}

		b := 0
		if i < len(s2) {
			b = order(rune(s2[i]))
		}

		if a != b {
			return a - b
		}
	}

}

// order function returns the number corresponding to rune
func order(r rune) int {
	// all the letters sort earlier than all the non-letters
	if unicode.IsLetter(r) {
		return int(r)
	}

	// a tilde sorts before anything
	if r == '~' {
		return -1
	}

	return int(r) + 256
}

func extract(version string) (defaultNumSlice, defaultStringSlice) {
	numbers := digitRegexp.FindAllString(version, -1)

	var dnum defaultNumSlice
	for _, number := range numbers {
		n, _ := strconv.Atoi(number)
		dnum = append(dnum, n)
	}

	s := nonDigitRegexp.FindAllString(version, -1)

	return dnum, defaultStringSlice(s)

}
