package version

import (
	apkver "github.com/knqyf263/go-apk-version"
	debver "github.com/knqyf263/go-deb-version"
	rpmver "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"
)

// Comparer defines the interface for version comparison
type Comparer interface {
	Compare(version1, version2 string) (int, error)
}

// DEBComparer implements Comparer for Debian/Ubuntu packages
type DEBComparer struct{}

// NewDEBComparer creates a new DEB version comparer
func NewDEBComparer() *DEBComparer {
	return &DEBComparer{}
}

// Compare compares two Debian package versions
// Returns:
//   - positive if version1 > version2
//   - negative if version1 < version2
//   - zero if version1 == version2
func (c *DEBComparer) Compare(version1, version2 string) (int, error) {
	v1, err := debver.NewVersion(version1)
	if err != nil {
		return 0, err
	}

	v2, err := debver.NewVersion(version2)
	if err != nil {
		return 0, err
	}

	return v1.Compare(v2), nil
}

// APKComparer implements Comparer for Alpine packages
type APKComparer struct{}

// NewAPKComparer creates a new APK version comparer
func NewAPKComparer() *APKComparer {
	return &APKComparer{}
}

// Compare compares two Alpine package versions
// Returns:
//   - positive if version1 > version2
//   - negative if version1 < version2
//   - zero if version1 == version2
func (c *APKComparer) Compare(version1, version2 string) (int, error) {
	v1, err := apkver.NewVersion(version1)
	if err != nil {
		return 0, xerrors.Errorf("failed to parse apk %q version: %w", version1, err)
	}

	v2, err := apkver.NewVersion(version2)
	if err != nil {
		return 0, xerrors.Errorf("failed to parse apk %q version: %w", version2, err)
	}

	return v1.Compare(v2), nil
}

// RPMComparer implements Comparer for RedHat packages
type RPMComparer struct{}

// NewRPMComparer creates a new RedHat version comparer
func NewRPMComparer() *RPMComparer {
	return &RPMComparer{}
}

// Compare compares two RedHat package versions
// Returns:
//   - positive if version1 > version2
//   - negative if version1 < version2
//   - zero if version1 == version2
func (c *RPMComparer) Compare(version1, version2 string) (int, error) {
	v1 := rpmver.NewVersion(version1)

	v2 := rpmver.NewVersion(version2)

	return v1.Compare(v2), nil
}
