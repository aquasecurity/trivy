package types

// VulnType represents vulnerability type
type VulnType = string

// SecurityCheck represents the type of security check
type SecurityCheck = string

const (
	// VulnTypeUnknown is a vulnerability type of unknown
	VulnTypeUnknown = VulnType("unknown")

	// VulnTypeOS is a vulnerability type of OS packages
	VulnTypeOS = VulnType("os")

	// VulnTypeLibrary is a vulnerability type of programming language dependencies
	VulnTypeLibrary = VulnType("library")

	// SecurityCheckUnknown is a security check of unknown
	SecurityCheckUnknown = SecurityCheck("unknown")

	// SecurityCheckVulnerability is a security check of vulnerabilities
	SecurityCheckVulnerability = SecurityCheck("vuln")

	// SecurityCheckConfig is a security check of misconfigurations
	SecurityCheckConfig = SecurityCheck("config")

	// SecurityCheckSecret is a security check of secrets
	SecurityCheckSecret = SecurityCheck("secret")
)

var (
	VulnTypes      = []string{VulnTypeOS, VulnTypeLibrary}
	SecurityChecks = []string{SecurityCheckVulnerability, SecurityCheckConfig, SecurityCheckSecret}
)
