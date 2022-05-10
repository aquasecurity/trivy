package semver

import (
	"bytes"
	"fmt"
	"math"
	"regexp"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-version/pkg/part"
	"github.com/aquasecurity/go-version/pkg/prerelease"
)

var (
	// ErrInvalidSemVer is returned when a given version is invalid
	ErrInvalidSemVer = xerrors.New("invalid semantic version")
)

var versionRegex *regexp.Regexp

// regex is the regular expression used to parse a SemVer string.
// See: https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
const regex string = `^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)` +
	`(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))` +
	`?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`

func init() {
	versionRegex = regexp.MustCompile(regex)
}

// Version represents a semantic version.
type Version struct {
	major, minor, patch part.Part
	preRelease          part.Parts
	buildMetadata       string
	original            string
}

// New returns an instance of Version
func New(major, minor, patch part.Part, pre part.Parts, metadata string) Version {
	return Version{
		major:         major,
		minor:         minor,
		patch:         patch,
		preRelease:    pre,
		buildMetadata: metadata,
	}
}

// Parse parses a given version and returns a new instance of Version
func Parse(v string) (Version, error) {
	m := versionRegex.FindStringSubmatch(v)
	if m == nil {
		return Version{}, ErrInvalidSemVer
	}

	major, err := part.NewUint64(m[versionRegex.SubexpIndex("major")])
	if err != nil {
		return Version{}, xerrors.Errorf("invalid major version: %w", err)
	}

	minor, err := part.NewUint64(m[versionRegex.SubexpIndex("minor")])
	if err != nil {
		return Version{}, xerrors.Errorf("invalid minor version: %w", err)
	}

	patch, err := part.NewUint64(m[versionRegex.SubexpIndex("patch")])
	if err != nil {
		return Version{}, xerrors.Errorf("invalid patch version: %w", err)
	}

	return Version{
		major:         major,
		minor:         minor,
		patch:         patch,
		preRelease:    part.NewParts(m[versionRegex.SubexpIndex("prerelease")]),
		buildMetadata: m[versionRegex.SubexpIndex("buildmetadata")],
		original:      v,
	}, nil
}

// String converts a Version object to a string.
func (v Version) String() string {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "%d.%d.%d", v.major, v.minor, v.patch)
	if !v.preRelease.IsNull() {
		fmt.Fprintf(&buf, "-%s", v.preRelease)
	}
	if v.buildMetadata != "" {
		fmt.Fprintf(&buf, "+%s", v.buildMetadata)
	}

	return buf.String()
}

// IsAny returns true if major, minor or patch is wild card
func (v Version) IsAny() bool {
	return v.major.IsAny() || v.minor.IsAny() || v.patch.IsAny()
}

// Release returns the version without pre-release.
// e.g. 1.2.3-alpha => 1.2.3
func (v Version) Release() Version {
	v.preRelease = part.Parts{}
	return v
}

// IncMajor produces the next major version.
// e.g. 1.2.3 => 2.0.0
func (v Version) IncMajor() Version {
	v.major = v.major.(part.Uint64) + 1
	v.minor = part.Zero
	v.patch = part.Zero
	v.preRelease = part.Parts{}
	v.buildMetadata = ""
	v.original = v.String()
	return v
}

// IncMinor produces the next minor version.
func (v Version) IncMinor() Version {
	v.minor = v.minor.(part.Uint64) + 1
	v.patch = part.Zero
	v.preRelease = part.Parts{}
	v.buildMetadata = ""
	v.original = v.String()
	return v
}

// IncPatch produces the next patch version.
func (v Version) IncPatch() Version {
	v.patch = v.patch.(part.Uint64) + 1
	v.preRelease = part.Parts{}
	v.buildMetadata = ""
	v.original = v.String()
	return v
}

// Min produces the minimum version if it includes wild card.
// 1.2.* => 1.2.0
// 1.*.* => 1.0.0
func (v Version) Min() Version {
	if v.major.IsAny() {
		v.major = part.Zero
	}
	if v.minor.IsAny() {
		v.minor = part.Zero
	}
	if v.patch.IsAny() {
		v.patch = part.Zero
	}
	if v.preRelease.IsAny() {
		v.preRelease = part.Parts{}
	}
	v.buildMetadata = ""
	v.original = v.String()
	return v
}

// Original returns the original value.
func (v Version) Original() string {
	return v.original
}

// Major returns the major version.
func (v Version) Major() part.Part {
	return v.major
}

// Minor returns the minor version.
func (v Version) Minor() part.Part {
	return v.minor
}

// Patch returns the patch version.
func (v Version) Patch() part.Part {
	return v.patch
}

// PreRelease returns the pre-release version.
func (v Version) PreRelease() part.Parts {
	return v.preRelease
}

// IsPreRelease returns if it is a pre-release version.
// 1.2.3       => false
// 1.2.3-alpha => true
func (v Version) IsPreRelease() bool {
	return !v.preRelease.IsNull()
}

// Metadata returns the metadata on the version.
func (v Version) Metadata() string {
	return v.buildMetadata
}

// LessThan tests if one version is less than another one.
func (v Version) LessThan(o Version) bool {
	return v.Compare(o) < 0
}

// LessThanOrEqual tests if this version is less than or equal to another version.
func (v Version) LessThanOrEqual(o Version) bool {
	return v.Compare(o) <= 0
}

// GreaterThan tests if one version is greater than another one.
func (v Version) GreaterThan(o Version) bool {
	return v.Compare(o) > 0
}

// GreaterThanOrEqual tests if this version is greater than or equal to another version.
func (v Version) GreaterThanOrEqual(o Version) bool {
	return v.Compare(o) >= 0
}

// Equal tests if two versions are equal to each other.
// Note, versions can be equal with different metadata since metadata
// is not considered part of the comparable version.
func (v Version) Equal(o Version) bool {
	return v.Compare(o) == 0
}

// Compare compares this version to another one. It returns -1, 0, or 1 if
// the version smaller, equal, or larger than the other version.
//
// Versions are compared by X.Y.Z. Build metadata is ignored. Prerelease is
// lower than the version without a prerelease.
func (v Version) Compare(o Version) int {
	// Compare the major, minor, and patch version for differences. If a
	// difference is found return the comparison.
	result := v.major.Compare(o.major)
	if result != 0 || v.major.IsAny() || o.major.IsAny() {
		return result
	}
	result = v.minor.Compare(o.minor)
	if result != 0 || v.minor.IsAny() || o.minor.IsAny() {
		return result
	}
	result = v.patch.Compare(o.patch)
	if result != 0 || v.patch.IsAny() || o.patch.IsAny() {
		return result
	}

	// At this point the major, minor, and patch versions are the same.
	return prerelease.Compare(v.preRelease, o.preRelease)
}

// TildeBump returns the maximum version of tilde ranges
// e.g. ~1.2.3 := >=1.2.3 <1.3.0
// In this case, it returns 1.3.0
// ref. https://docs.npmjs.com/cli/v6/using-npm/semver#tilde-ranges-123-12-1
func (v Version) TildeBump() Version {
	switch {
	case v.major.IsAny(), v.major.IsEmpty():
		v.major = part.Uint64(math.MaxUint64)
		return v
	case v.minor.IsAny(), v.minor.IsEmpty():
		// e.g. 1 => 2.0.0
		return v.IncMajor()
	case v.patch.IsAny(), v.patch.IsEmpty():
		// e.g. 1.2 => 1.3.0
		return v.IncMinor()
	default:
		// e.g. 1.2.3 => 1.3.0
		return v.IncMinor()
	}
}

// CaretBump returns the maximum version of caret ranges
// e.g. ^1.2.3 := >=1.2.3 <2.0.0
// In this case, it returns 2.0.0
// ref. https://docs.npmjs.com/cli/v6/using-npm/semver#caret-ranges-123-025-004
func (v Version) CaretBump() Version {
	switch {
	case v.major.IsAny(), v.major.IsEmpty():
		v.major = part.Uint64(math.MaxUint64)
		return v
	case v.major.(part.Uint64) != 0:
		// e.g. 1 => 2.0.0
		return v.IncMajor()
	case v.minor.IsAny(), v.minor.IsEmpty():
		// e.g. 0 => 1.0.0
		return v.IncMajor()
	case v.minor.(part.Uint64) != 0:
		// e.g. 0.2.3 => 0.3.0
		return v.IncMinor()
	case v.patch.IsAny(), v.patch.IsEmpty():
		// e.g. 0.0 => 0.1.0
		return v.IncMinor()
	default:
		// e.g. 0.0.3 => 0.0.4
		return v.IncPatch()
	}
}
