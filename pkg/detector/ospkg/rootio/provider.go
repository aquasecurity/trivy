package rootio

import (
	"regexp"

	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
)

var (
	// debianRootIOPattern matches Debian/Ubuntu Root.io version pattern: .root.io
	debianRootIOPattern = regexp.MustCompile(`\.root\.io`)
	// alpineRootIOPattern matches Alpine Root.io version pattern: -r\d007\d (e.g., -r10071, -r20072)
	alpineRootIOPattern = regexp.MustCompile(`-r\d007\d`)
)

// Provider creates a Root.io driver if Root.io packages are detected
func Provider(osFamily ftypes.OSType, pkgs []ftypes.Package) driver.Driver {
	if !isRootIOEnvironment(osFamily, pkgs) {
		return nil
	}
	return NewScanner(osFamily)
}

// isRootIOEnvironment detects if the environment is Root.io based on package suffixes
func isRootIOEnvironment(osFamily ftypes.OSType, pkgs []ftypes.Package) bool {
	switch osFamily {
	case ftypes.Debian, ftypes.Ubuntu:
		return hasPackageWithPattern(pkgs, debianRootIOPattern)
	case ftypes.Alpine:
		return hasPackageWithPattern(pkgs, alpineRootIOPattern)
	default:
		return false
	}
}

// hasPackageWithPattern checks if any package version matches the specified pattern
func hasPackageWithPattern(pkgs []ftypes.Package, pattern *regexp.Regexp) bool {
	for _, pkg := range pkgs {
		if pattern.MatchString(utils.FormatVersion(pkg)) {
			return true
		}
	}
	return false
}
