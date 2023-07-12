package types

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// ScanOptions holds the attributes for scanning vulnerabilities
type ScanOptions struct {
	VulnType            []string
	Scanners            Scanners
	ImageConfigScanners Scanners // Scanners for container image configuration
	ScanRemovedPackages bool
	ListAllPackages     bool
	LicenseCategories   map[types.LicenseCategory][]string
	FilePatterns        []string
	IncludeDevDeps      bool
}
