package rapidfort

import (
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Supplier creates a RapidFort driver for curated images, which the RapidFort
// fanal analyzer marks by setting OS.Supplier.
func Supplier(os ftypes.OS, _ []ftypes.Package) driver.Driver {
	if os.Supplier != ftypes.SupplierRapidFort {
		return nil
	}
	switch os.Family {
	case ftypes.Ubuntu, ftypes.Alpine, ftypes.RedHat:
		return NewScanner(os.Family)
	}
	return nil
}
