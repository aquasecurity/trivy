package seal

import (
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Provider creates a Root.io driver if Root.io packages are detected
func Provider(osFamily ftypes.OSType, pkgs []ftypes.Package) driver.Driver {
	for _, pkg := range pkgs {
		if sealPkg(pkg) {
			return NewScanner(osFamily)
		}
	}
	return nil
}
