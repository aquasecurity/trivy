package types

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// ScanTarget holds the attributes for scanning.
type ScanTarget struct {
	Name              string // container image name, file path, etc
	OS                types.OS
	Repository        *types.Repository
	Packages          types.Packages
	Applications      []types.Application
	Misconfigurations []types.Misconfiguration
	Secrets           []types.Secret
	Licenses          []types.LicenseFile

	// CustomResources hold analysis results from custom analyzers.
	// It is for extensibility and not used in OSS.
	CustomResources []types.CustomResource
}

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
