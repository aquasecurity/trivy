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
			sarifRuleName:     "OS Package Vulnerability (Ubuntu)",
		},
		{
			vulnerabilityType: vulnerability.Alpine,
			sarifRuleName:     "OS Package Vulnerability (Alpine)",
		},
		{
			vulnerabilityType: vulnerability.RedHat,
			sarifRuleName:     "OS Package Vulnerability (Redhat)",
		},
		{
			vulnerabilityType: vulnerability.RedHatOVAL,
			sarifRuleName:     "OS Package Vulnerability (Redhat-Oval)",
		},
		{
			vulnerabilityType: vulnerability.Debian,
			sarifRuleName:     "OS Package Vulnerability (Debian)",
		},
		{
			vulnerabilityType: vulnerability.DebianOVAL,
			sarifRuleName:     "OS Package Vulnerability (Debian-Oval)",
		},
		{
			vulnerabilityType: vulnerability.Fedora,
			sarifRuleName:     "OS Package Vulnerability (Fedora)",
		},
		{
			vulnerabilityType: vulnerability.Amazon,
			sarifRuleName:     "OS Package Vulnerability (Amazon)",
		},
		{
			vulnerabilityType: vulnerability.OracleOVAL,
			sarifRuleName:     "OS Package Vulnerability (Oracle-Oval)",
		},
		{
			vulnerabilityType: vulnerability.SuseCVRF,
			sarifRuleName:     "OS Package Vulnerability (Suse-Cvrf)",
		},
		{
			vulnerabilityType: vulnerability.OpenSuseCVRF,
			sarifRuleName:     "OS Package Vulnerability (Opensuse-Cvrf)",
		},
		{
			vulnerabilityType: vulnerability.Photon,
			sarifRuleName:     "OS Package Vulnerability (Photon)",
		},
		{
			vulnerabilityType: vulnerability.CentOS,
			sarifRuleName:     "OS Package Vulnerability (Centos)",
		},
		{
			vulnerabilityType: "npm",
			sarifRuleName:     "Programming Language Vulnerability (Npm)",
		},
		{
			vulnerabilityType: "yarn",
			sarifRuleName:     "Programming Language Vulnerability (Yarn)",
		},
		{
			vulnerabilityType: "nuget",
			sarifRuleName:     "Programming Language Vulnerability (Nuget)",
		},
		{
			vulnerabilityType: "pipenv",
			sarifRuleName:     "Programming Language Vulnerability (Pipenv)",
		},
		{
			vulnerabilityType: "poetry",
			sarifRuleName:     "Programming Language Vulnerability (Poetry)",
		},
		{
			vulnerabilityType: "bundler",
			sarifRuleName:     "Programming Language Vulnerability (Bundler)",
		},
		{
			vulnerabilityType: "cargo",
			sarifRuleName:     "Programming Language Vulnerability (Cargo)",
		},
		{
			vulnerabilityType: "composer",
			sarifRuleName:     "Programming Language Vulnerability (Composer)",
		},
		{
			vulnerabilityType: "redis",
			sarifRuleName:     "Other Vulnerability (Redis)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.vulnerabilityType, func(t *testing.T) {
			assert.Equal(t, tc.sarifRuleName, toSarifRuleName(tc.vulnerabilityType), tc.vulnerabilityType)
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
			severity:        "UNKNOWN",
			sarifErrorLevel: "note",
		},
		{
			severity:        "OTHER",
			sarifErrorLevel: "none",
		},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			assert.Equal(t, tc.sarifErrorLevel, toSarifErrorLevel(tc.severity), tc.severity)
		})
	}
}
