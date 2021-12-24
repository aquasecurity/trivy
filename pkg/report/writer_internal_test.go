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
			sarifRuleName:     sarifOsPackageVulnerability,
		},
		{
			vulnerabilityType: vulnerability.Alpine,
			sarifRuleName:     sarifOsPackageVulnerability,
		},
		{
			vulnerabilityType: vulnerability.RedHat,
			sarifRuleName:     sarifOsPackageVulnerability,
		},
		{
			vulnerabilityType: vulnerability.Debian,
			sarifRuleName:     sarifOsPackageVulnerability,
		},
		{
			vulnerabilityType: vulnerability.Fedora,
			sarifRuleName:     sarifOsPackageVulnerability,
		},
		{
			vulnerabilityType: vulnerability.Amazon,
			sarifRuleName:     sarifOsPackageVulnerability,
		},
		{
			vulnerabilityType: vulnerability.Photon,
			sarifRuleName:     sarifOsPackageVulnerability,
		},
		{
			vulnerabilityType: vulnerability.CentOS,
			sarifRuleName:     sarifOsPackageVulnerability,
		},
		{
			vulnerabilityType: "npm",
			sarifRuleName:     sarifLanguageSpecificVulnerability,
		},
		{
			vulnerabilityType: "yarn",
			sarifRuleName:     sarifLanguageSpecificVulnerability,
		},
		{
			vulnerabilityType: "nuget",
			sarifRuleName:     sarifLanguageSpecificVulnerability,
		},
		{
			vulnerabilityType: "pipenv",
			sarifRuleName:     sarifLanguageSpecificVulnerability,
		},
		{
			vulnerabilityType: "poetry",
			sarifRuleName:     sarifLanguageSpecificVulnerability,
		},
		{
			vulnerabilityType: "bundler",
			sarifRuleName:     sarifLanguageSpecificVulnerability,
		},
		{
			vulnerabilityType: "cargo",
			sarifRuleName:     sarifLanguageSpecificVulnerability,
		},
		{
			vulnerabilityType: "composer",
			sarifRuleName:     sarifLanguageSpecificVulnerability,
		},
		{
			vulnerabilityType: "redis",
			sarifRuleName:     sarifOtherVulnerability,
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
