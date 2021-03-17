package types

import "github.com/aquasecurity/trivy/pkg/utils"

// VulnType represents vulnerability type
type VulnType = string

// SecurityCheck represents the type of security check
type SecurityCheck = string

const (
	// vulnerability types
	VulnTypeUnknown = VulnType("unknown")
	VulnTypeOS      = VulnType("os")
	VulnTypeLibrary = VulnType("library")

	// security checks
	SecurityCheckUnknown       = SecurityCheck("unknown")
	SecurityCheckVulnerability = SecurityCheck("vuln")
	SecurityCheckConfig        = SecurityCheck("config")
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
