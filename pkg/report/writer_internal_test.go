package report

import (
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/stretchr/testify/assert"
)

func TestReportWriter_toSarifRuleName(t *testing.T) {
	tests := []struct {
		vulnerabilityType string
		sarifRuleName     string
	}{
		{
			vulnerabilityType: vulnerability.Ubuntu,
			sarifRuleName:     "Os Package Vulnerability Ubuntu",
		},
		{
			vulnerabilityType: vulnerability.Alpine,
			sarifRuleName:     "Os Package Vulnerability Alpine",
		},
		{
			vulnerabilityType: vulnerability.RedHat,
			sarifRuleName:     "Os Package Vulnerability Redhat",
		},
		{
			vulnerabilityType: vulnerability.RedHatOVAL,
			sarifRuleName:     "Os Package Vulnerability Redhat-Oval",
		},
		{
			vulnerabilityType: vulnerability.Debian,
			sarifRuleName:     "Os Package Vulnerability Debian",
		},
		{
			vulnerabilityType: vulnerability.DebianOVAL,
			sarifRuleName:     "Os Package Vulnerability Debian-Oval",
		},
		{
			vulnerabilityType: vulnerability.Fedora,
			sarifRuleName:     "Os Package Vulnerability Fedora",
		},
		{
			vulnerabilityType: vulnerability.Amazon,
			sarifRuleName:     "Os Package Vulnerability Amazon",
		},
		{
			vulnerabilityType: vulnerability.OracleOVAL,
			sarifRuleName:     "Os Package Vulnerability Oracle-Oval",
		},
		{
			vulnerabilityType: vulnerability.SuseCVRF,
			sarifRuleName:     "Os Package Vulnerability Suse-Cvrf",
		},
		{
			vulnerabilityType: vulnerability.OpenSuseCVRF,
			sarifRuleName:     "Os Package Vulnerability Opensuse-Cvrf",
		},
		{
			vulnerabilityType: vulnerability.Photon,
			sarifRuleName:     "Os Package Vulnerability Photon",
		},
		{
			vulnerabilityType: vulnerability.CentOS,
			sarifRuleName:     "Os Package Vulnerability Centos",
		},
		{
			vulnerabilityType: "npm",
			sarifRuleName:     "Programming Language Vulnerability Npm",
		},
		{
			vulnerabilityType: "yarn",
			sarifRuleName:     "Programming Language Vulnerability Yarn",
		},
		{
			vulnerabilityType: "nuget",
			sarifRuleName:     "Programming Language Vulnerability Nuget",
		},
		{
			vulnerabilityType: "pipenv",
			sarifRuleName:     "Programming Language Vulnerability Pipenv",
		},
		{
			vulnerabilityType: "poetry",
			sarifRuleName:     "Programming Language Vulnerability Poetry",
		},
		{
			vulnerabilityType: "bundler",
			sarifRuleName:     "Programming Language Vulnerability Bundler",
		},
		{
			vulnerabilityType: "cargo",
			sarifRuleName:     "Programming Language Vulnerability Cargo",
		},
		{
			vulnerabilityType: "composer",
			sarifRuleName:     "Programming Language Vulnerability Composer",
		},
		{
			vulnerabilityType: "redis",
			sarifRuleName:     "Other Vulnerability Redis",
		},
	}
	for _, tc := range tests {
		t.Run(tc.vulnerabilityType, func(t *testing.T) {
			got := toSarifRuleName(tc.vulnerabilityType)
			assert.Equal(t, tc.sarifRuleName, got, tc.vulnerabilityType)
		})
	}
}

func TestReportWriter_toSarifErrorLevel(t *testing.T) {
	tests := []struct {
		severity        string
		sarifErrorLevel string
	}{
		{
			severity:        "CRITICAL",
			sarifErrorLevel: "error",
		},
		{
			severity:        "HIGH",
			sarifErrorLevel: "error",
		},
		{
			severity:        "MEDIUM",
			sarifErrorLevel: "warning",
		},
		{
			severity:        "LOW",
			sarifErrorLevel: "note",
		},
		{
			severity:        "Unknown",
			sarifErrorLevel: "note",
		},
		{
			severity:        "OTHER",
			sarifErrorLevel: "none",
		},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			got := toSarifErrorLevel(tc.severity)
			assert.Equal(t, tc.sarifErrorLevel, got, tc.severity)
		})
	}
}
