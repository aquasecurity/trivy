package ospkg

import (
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Bridge to expose ospkg internals to tests in the ospkg_test package.

// Drivers exports drivers for testing.
var Drivers = func() map[ftypes.OSType]driver.Driver { return drivers }
