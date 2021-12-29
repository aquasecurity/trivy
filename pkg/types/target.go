package types

import "github.com/aquasecurity/trivy/pkg/utils"

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
)

var (
	vulnTypes      = []string{VulnTypeOS, VulnTypeLibrary}
	securityChecks = []string{SecurityCheckVulnerability, SecurityCheckConfig}
)

// NewVulnType returns an instance of VulnType
func NewVulnType(s string) VulnType {
	if utils.StringInSlice(s, vulnTypes) {
		return s
	}
	return VulnTypeUnknown
}

// NewSecurityCheck returns an instance of SecurityCheck
func NewSecurityCheck(s string) SecurityCheck {
	if utils.StringInSlice(s, securityChecks) {
		return s
	}
	return SecurityCheckUnknown
}
