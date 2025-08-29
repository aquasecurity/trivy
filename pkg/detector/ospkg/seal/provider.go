package seal

import (
	"slices"

	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Provider creates a Root.io driver if Root.io packages are detected
func Provider(osFamily ftypes.OSType, pkgs []ftypes.Package) driver.Driver {
	if slices.ContainsFunc(pkgs, sealPkg) {
		return NewScanner(osFamily)
	}
	return nil
}
