package activestate

import (
	"context"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Scanner implements the ActiveState scanner
type Scanner struct{}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	return &Scanner{}
}

// Detect returns an empty result because ActiveState images currently don't contain OS packages.
func (s *Scanner) Detect(_ context.Context, _ string, _ *ftypes.Repository, _ []ftypes.Package) ([]types.DetectedVulnerability, error) {
	return nil, nil
}

// IsSupportedVersion always returns true because ActiveState doesn't have EOL versions.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}
