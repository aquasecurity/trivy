package rapidfort

import (
	"context"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// BaseOS exposes the Scanner's baseOS so TestSupplier can pin which
// family the returned Scanner was built for; a NotNil check alone would
// pass even if Supplier handed back the wrong family's Scanner.
func (s *Scanner) BaseOS() ftypes.OSType {
	return s.baseOS
}

// IsVulnerable exports isVulnerable for testing.
func (s *Scanner) IsVulnerable(ctx context.Context, installedVersion string, adv dbTypes.Advisory) bool {
	return s.isVulnerable(ctx, installedVersion, adv)
}

// RpmDistTag exports rpmDistTag for testing.
func RpmDistTag(ver string) (tag, num string) {
	return rpmDistTag(ver)
}

// DpkgHasRfMarker exports dpkgHasRfMarker for testing.
func DpkgHasRfMarker(ver string) bool {
	return dpkgHasRfMarker(ver)
}
