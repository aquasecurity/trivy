package seal

import (
	"slices"

	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

var (
	supportedOSFamilies = set.New(
		ftypes.Alpine,
		ftypes.CBLMariner,
		ftypes.CentOS,
		ftypes.RedHat,
		ftypes.Debian,
		ftypes.Oracle,
		ftypes.Ubuntu,
	)
)

// Supplier creates a Seal driver if Seal packages are detected
func Supplier(os ftypes.OS, pkgs []ftypes.Package) driver.Driver {
	if supportedOSFamilies.Contains(os.Family) && slices.ContainsFunc(pkgs, sealPkg) {
		return NewScanner(os.Family)
	}
	return nil
}
