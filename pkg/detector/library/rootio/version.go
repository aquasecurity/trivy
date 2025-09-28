package rootio

import (
	"strings"

	version "github.com/aquasecurity/go-pep440-version"
)

const (
	// VersionSuffix is the Root.io version suffix
	VersionSuffix = ".root.io"
)

// NormalizeVersion removes the Root.io suffix from a version string for comparison
func NormalizeVersion(ver string) string {
	if strings.HasSuffix(ver, VersionSuffix) {
		return strings.TrimSuffix(ver, VersionSuffix)
	}
	return ver
}

// AddVersionSuffix adds the Root.io suffix to a version string if not already present
func AddVersionSuffix(ver string) string {
	if !strings.HasSuffix(ver, VersionSuffix) {
		return ver + VersionSuffix
	}
	return ver
}

// IsValidVersion checks if a version string is valid after normalizing for Root.io
func IsValidVersion(ver string) bool {
	normalizedVer := NormalizeVersion(ver)
	_, err := version.Parse(normalizedVer)
	return err == nil
}

// HasRootIOSuffix checks if a version has the Root.io suffix
func HasRootIOSuffix(ver string) bool {
	return strings.HasSuffix(ver, VersionSuffix)
}
