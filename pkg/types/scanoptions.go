package types

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// ScanOptions holds the attributes for scanning vulnerabilities
type ScanOptions struct {
	VulnType            []string
	SecurityChecks      []string
	ScanRemovedPackages bool
	Platform            string
	ListAllPackages     bool
	LicenseCategories   map[types.LicenseCategory][]string
	FilePatterns        []string
}
