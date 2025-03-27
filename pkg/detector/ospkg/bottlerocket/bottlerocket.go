package bottlerocket

import (
	"context"

	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Scanner implements the Bottlerocket scanner
type Scanner struct {
}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	return &Scanner{}
}

// Detect vulnerabilities in package using Bottlerocket scanner
func (s *Scanner) Detect(ctx context.Context, osVer string, repo *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	return nil, nil
}

func (s *Scanner) IsSupportedVersion(ctx context.Context, osFamily ftypes.OSType, osVer string) bool {
	return osver.Supported(ctx, nil, osFamily, osver.Minor(osVer))
}
