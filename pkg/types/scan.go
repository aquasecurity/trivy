package types

import (
	"slices"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// PkgType represents package type
type PkgType = string

// Scanner represents the type of security scanning
type Scanner string

// Scanners is a slice of scanners
type Scanners []Scanner

const (
	// PkgTypeUnknown is a package type of unknown
	PkgTypeUnknown PkgType = "unknown"

	// PkgTypeOS is a package type of OS packages
	PkgTypeOS PkgType = "os"

	// PkgTypeLibrary is a package type of programming language dependencies
	PkgTypeLibrary PkgType = "library"

	// UnknownScanner is the scanner of unknown
	UnknownScanner Scanner = "unknown"

	// NoneScanner is the scanner of none
	NoneScanner Scanner = "none"

	// SBOMScanner is the virtual scanner of SBOM, which cannot be enabled by the user
	SBOMScanner Scanner = "sbom"

	// VulnerabilityScanner is the scanner of vulnerabilities
	VulnerabilityScanner Scanner = "vuln"

	// MisconfigScanner is the scanner of misconfigurations
	MisconfigScanner Scanner = "misconfig"

	// SecretScanner is the scanner of secrets
	SecretScanner Scanner = "secret"

	// RBACScanner is the scanner of rbac assessment
	RBACScanner Scanner = "rbac"

	// LicenseScanner is the scanner of licenses
	LicenseScanner Scanner = "license"
)

var (
	PkgTypes = []string{
		PkgTypeOS,
		PkgTypeLibrary,
	}

	AllScanners = Scanners{
		VulnerabilityScanner,
		MisconfigScanner,
		RBACScanner,
		SecretScanner,
		LicenseScanner,
		NoneScanner,
	}

	// AllImageConfigScanners has a list of available scanners on container image config.
	// The container image in container registries consists of manifest, config and layers.
	// Trivy is also able to detect security issues on the image config.
	AllImageConfigScanners = Scanners{
		MisconfigScanner,
		SecretScanner,
		NoneScanner,
	}
)

func (scanners *Scanners) Enable(s Scanner) {
	if !scanners.Enabled(s) {
		*scanners = append(*scanners, s)
	}
}

func (scanners *Scanners) Enabled(s Scanner) bool {
	return slices.Contains(*scanners, s)
}

// AnyEnabled returns true if any of the passed scanners is included.
func (scanners *Scanners) AnyEnabled(ss ...Scanner) bool {
	for _, s := range ss {
		if scanners.Enabled(s) {
			return true
		}
	}
	return false
}

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
	PkgTypes            []string
	PkgRelationships    []types.Relationship
	Scanners            Scanners
	ImageConfigScanners Scanners // Scanners for container image configuration
	ScanRemovedPackages bool
	LicenseCategories   map[types.LicenseCategory][]string
	FilePatterns        []string
	IncludeDevDeps      bool
	Distro              types.OS // Forced OS
}
