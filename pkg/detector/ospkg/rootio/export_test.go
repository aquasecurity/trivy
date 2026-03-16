package rootio

import (
	"context"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

// Bridge to expose rootio scanner internals to tests in the rootio_test package.

// IsVulnerable exports isVulnerable for testing.
func (s *Scanner) IsVulnerable(ctx context.Context, installedVersion string, adv dbTypes.Advisory) bool {
	return s.isVulnerable(ctx, installedVersion, adv)
}
