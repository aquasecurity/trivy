package version

import (
	apkver "github.com/knqyf263/go-apk-version"
	debver "github.com/knqyf263/go-deb-version"
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
		return 0, err
	}

	v2, err := apkver.NewVersion(version2)
	if err != nil {
		return 0, err
	}

	return v1.Compare(v2), nil
}
