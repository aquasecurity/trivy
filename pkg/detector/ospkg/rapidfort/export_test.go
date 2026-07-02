package rapidfort

import (
	"context"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

// IsVulnerable exports isVulnerable for testing.
func (s *Scanner) IsVulnerable(ctx context.Context, installedVersion, identifier string, isRFPackage bool, adv dbTypes.Advisory) bool {
	return s.isVulnerable(ctx, installedVersion, identifier, isRFPackage, adv)
}
