package rootio

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Provider creates a Root.io driver if Root.io packages are detected
func Provider(osFamily ftypes.OSType, pkgs []ftypes.Package) driver.Driver {
	if !isRootIOEnvironment(osFamily, pkgs) {
		return nil
	}
	scanner := NewScanner(osFamily)
	return &scanner
}

// isRootIOEnvironment detects if the environment is Root.io based on package suffixes
func isRootIOEnvironment(osFamily ftypes.OSType, pkgs []ftypes.Package) bool {
	switch osFamily {
	case ftypes.Debian, ftypes.Ubuntu:
		return hasPackageWithSuffix(pkgs, "root.io")
	case ftypes.Alpine:
		return hasPackageWithSuffix(pkgs, "roo7")
	default:
		return false
	}
}

// hasPackageWithSuffix checks if any package version contains the specified suffix
func hasPackageWithSuffix(pkgs []ftypes.Package, suffix string) bool {
	for _, pkg := range pkgs {
		if strings.Contains(pkg.Version, suffix) {
			return true
		}
	}
	return false
}
