package version

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-version/pkg/part"
	"github.com/aquasecurity/go-version/pkg/prerelease"
)

// The compiled regular expression used to test the validity of a version.
var (
	versionRegex *regexp.Regexp
)

const (
	// The raw regular expression string used for testing the validity of a version.
	regex = `v?([0-9]+(\.[0-9]+)*)` +
		`(-([0-9]+[0-9A-Za-z\-~]*(\.[0-9A-Za-z\-~]+)*)|(-?([A-Za-z\-~]+[0-9A-Za-z\-~]*(\.[0-9A-Za-z\-~]+)*)))?` +
		`(\+([0-9A-Za-z\-~]+(\.[0-9A-Za-z\-~]+)*))?` +
		`?`
)

// Version represents a single version.
type Version struct {
	segments      []part.Uint64
	preRelease    part.Parts
	buildMetadata string
	original      string
}

func init() {
	versionRegex = regexp.MustCompile("^" + regex + "$")
}

// Parse parses the given version and returns a new Version.
func Parse(v string) (Version, error) {
	matches := versionRegex.FindStringSubmatch(v)
	if matches == nil {
		return Version{}, xerrors.Errorf("malformed version: %s", v)
	}

	var segments []part.Uint64
	for _, str := range strings.Split(matches[1], ".") {
		val, err := part.NewUint64(str)
		if err != nil {
			return Version{}, xerrors.Errorf("error parsing version: %w", err)
		}

		segments = append(segments, val)
	}

	pre := matches[7]
	if pre == "" {
		pre = matches[4]
	}

	return Version{
		segments:      segments,
		buildMetadata: matches[10],
		preRelease:    part.NewParts(pre),
		original:      v,
	}, nil
}

// Compare compares this version to another version. This
// returns -1, 0, or 1 if this version is smaller, equal,
// or larger than the other version, respectively.
func (v Version) Compare(other Version) int {
	// A quick, efficient equality check
	if v.String() == other.String() {
		return 0
	}

	p1 := part.Uint64SliceToParts(v.segments).Normalize()
	p2 := part.Uint64SliceToParts(other.segments).Normalize()

	p1 = p1.Padding(len(p2), part.Zero)
	p2 = p2.Padding(len(p1), part.Zero)

	if result := p1.Compare(p2); result != 0 {
		return result
	}

	return prerelease.Compare(v.preRelease, other.preRelease)
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

// String returns the full version string included pre-release
// and metadata information.
func (v Version) String() string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%d", v.segments[0])
	for _, s := range v.segments[1:len(v.segments)] {
		fmt.Fprintf(&buf, ".%d", s)
	}

	if !v.preRelease.IsNull() {
		fmt.Fprintf(&buf, "-%s", v.preRelease)
	}
	if v.buildMetadata != "" {
		fmt.Fprintf(&buf, "+%s", v.buildMetadata)
	}

	return buf.String()
}

// Original returns the original parsed version as-is, including any
// potential whitespace, `v` prefix, etc.
func (v Version) Original() string {
	return v.original
}

// PessimisticBump returns the maximum version of "~>"
// It works like Gem::Version.bump()
// https://docs.ruby-lang.org/en/2.6.0/Gem/Version.html#method-i-bump
func (v Version) PessimisticBump() Version {
	size := len(v.segments)
	if size == 1 {
		v.segments[0] += 1
		return v
	}

	v.segments[size-1] = 0
	v.segments[size-2] += 1

	v.preRelease = part.Parts{}
	v.buildMetadata = ""

	return v
}

// TildeBump returns the maximum version of "~"
// https://docs.npmjs.com/cli/v6/using-npm/semver#tilde-ranges-123-12-1
func (v Version) TildeBump() Version {
	if len(v.segments) == 2 {
		v.segments[1] += 1
		return v
	}

	return v.PessimisticBump()
}

// CaretBump returns the maximum version of "^"
// https://docs.npmjs.com/cli/v6/using-npm/semver#caret-ranges-123-025-004
func (v Version) CaretBump() Version {
	found := -1
	for i, s := range v.segments {
		if s != 0 {
			v.segments[i] += 1
			found = i
			break
		}
	}

	if found >= 0 {
		// zero padding
		// ^1.2.3 => 2.0.0
		for i := found + 1; i < len(v.segments); i++ {
			v.segments[i] = 0
		}
	} else {
		// ^0.0 => 0.1
		v.segments[len(v.segments)-1] += 1
	}

	v.preRelease = part.Parts{}
	v.buildMetadata = ""

	return v
}
