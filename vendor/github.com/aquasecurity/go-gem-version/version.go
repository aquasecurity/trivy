package gem

import (
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-version/pkg/part"
)

var (
	// The compiled regular expression used to test the validity of a version.
	versionRegexp *regexp.Regexp
	segmentRegexp *regexp.Regexp

	// ErrInvalidSemVer is returned when a given version is invalid
	ErrInvalidVersion = xerrors.New("invalid gem version")
)

const (
	// ref. https://github.com/rubygems/rubygems/blob/6914b4ec439ae1e7079b3c08576cb3fbce68aa69/lib/rubygems/version.rb#L157
	versionPattern string = `[0-9]+(\.[0-9a-zA-Z]+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?`
	segmentPattern string = `[0-9]+|[a-zA-Z]`
)

func init() {
	versionRegexp = regexp.MustCompile(`^\s*(` + versionPattern + `)?\s*$`)
	segmentRegexp = regexp.MustCompile(segmentPattern)
}

type Version struct {
	version         string
	numericSegments part.Parts
	stringSegments  part.Parts
}

// NewVersion returns an instance of Version
// ref. https://github.com/rubygems/rubygems/blob/6914b4ec439ae1e7079b3c08576cb3fbce68aa69/lib/rubygems/version.rb#L212-L222
func NewVersion(version string) (Version, error) {
	if !versionRegexp.MatchString(version) {
		return Version{}, ErrInvalidVersion
	}

	version = strings.TrimSpace(version)
	if version == "" {
		version = "0"
	}

	version = strings.ReplaceAll(version, "-", ".pre.")
	ns, ss := splitSegments(version)

	return Version{
		version:         version,
		numericSegments: ns,
		stringSegments:  ss,
	}, nil
}

func (v Version) canonicalSegments() part.Parts {
	ns := v.numericSegments.Normalize()
	ss := v.stringSegments.Normalize()
	return append(ns, ss...)
}

// ref. https://github.com/rubygems/rubygems/blob/6914b4ec439ae1e7079b3c08576cb3fbce68aa69/lib/rubygems/version.rb#L390-L398
func splitSegments(version string) (part.Parts, part.Parts) {
	var numericSegments, stringSegments part.Parts
	var err error

	isNumeric := true
	for _, seg := range segmentRegexp.FindAllString(version, -1) {
		var p part.Part
		p, err = part.NewUint64(seg)
		if err != nil {
			isNumeric = false
			p = part.NewPreString(seg)
		}

		if isNumeric {
			numericSegments = append(numericSegments, p)
		} else {
			stringSegments = append(stringSegments, p)
		}
	}
	return numericSegments, stringSegments
}

// Compare compares this version to another version. This
// returns -1, 0, or 1 if this version is smaller, equal,
// or larger than the other version, respectively.
func (v Version) Compare(other Version) int {
	if v.version == other.version {
		return 0
	}

	cs1 := v.canonicalSegments()
	cs2 := other.canonicalSegments()

	s1 := cs1.Padding(len(cs2), part.Zero)
	s2 := cs2.Padding(len(cs1), part.Zero)

	return s1.Compare(s2)
}

// String returns the full version string
func (v Version) String() string {
	return v.version
}

// Equal tests if two versions are equal.
func (v Version) Equal(o Version) bool {
	return v.Compare(o) == 0
}

// GreaterThan tests if this version is greater than another version.
func (v Version) GreaterThan(o Version) bool {
	return v.Compare(o) > 0
}

// GreaterThanOrEqual tests if this version is greater than or equal to another version.
func (v Version) GreaterThanOrEqual(o Version) bool {
	return v.Compare(o) >= 0
}

// LessThan tests if this version is less than another version.
func (v Version) LessThan(o Version) bool {
	return v.Compare(o) < 0
}

// LessThanOrEqual tests if this version is less than or equal to another version.
func (v Version) LessThanOrEqual(o Version) bool {
	return v.Compare(o) <= 0
}

// Release returns the release for this version (e.g. 1.2.0.a -> 1.2.0).
// Non-prerelease versions return themselves.
// https://docs.ruby-lang.org/en/2.6.0/Gem/Version.html#method-i-release
func (v Version) Release() Version {
	v.stringSegments = part.Parts{}
	v.version = v.numericSegments.String()
	return v
}

// Bump returns a new version object where the next to the last revision
// number is one greater (e.g., 5.3.1 => 5.4).
// https://docs.ruby-lang.org/en/2.6.0/Gem/Version.html#method-i-release
func (v Version) Bump() Version {
	last := len(v.numericSegments)
	if last <= 1 {
		last = 2
	}
	v.numericSegments = v.numericSegments[:last-1]
	v.numericSegments[last-2] = v.numericSegments[last-2].(part.Uint64) + 1
	v.version = v.numericSegments.String()

	return v.Release()
}
