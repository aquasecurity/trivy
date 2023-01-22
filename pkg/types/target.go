package types

// VulnType represents vulnerability type
type VulnType = string

// Scanner represents the type of security scanning
type Scanner = string

const (
	// VulnTypeUnknown is a vulnerability type of unknown
	VulnTypeUnknown = VulnType("unknown")

	// VulnTypeOS is a vulnerability type of OS packages
	VulnTypeOS = VulnType("os")

	// VulnTypeLibrary is a vulnerability type of programming language dependencies
	VulnTypeLibrary = VulnType("library")

	// ScannerUnknown is the scanner of unknown
	ScannerUnknown = Scanner("unknown")

	// VulnerabilityScanner is the scanner of vulnerabilities
	VulnerabilityScanner = Scanner("vuln")

	// MisconfigScanner is the scanner of misconfigurations
	MisconfigScanner = Scanner("config")

	// SecretScanner is the scanner of secrets
	SecretScanner = Scanner("secret")

	// RBACScanner is the scanner of rbac assessment
	RBACScanner = Scanner("rbac")

	// LicenseScanner is the scanner of licenses
	LicenseScanner = Scanner("license")
)

var (
	VulnTypes = []string{
		VulnTypeOS,
		VulnTypeLibrary,
	}
	Scanners = []string{
		VulnerabilityScanner,
		MisconfigScanner,
		RBACScanner,
		SecretScanner,
		LicenseScanner,
	}
)
