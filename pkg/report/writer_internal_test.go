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
			sarifRuleName:     "OsPackageVulnerability",
		},
		{
			vulnerabilityType: vulnerability.Alpine,
			sarifRuleName:     "OsPackageVulnerability",
		},
		{
			vulnerabilityType: vulnerability.RedHat,
			sarifRuleName:     "OsPackageVulnerability",
		},
		{
			vulnerabilityType: vulnerability.RedHatOVAL,
			sarifRuleName:     "OsPackageVulnerability",
		},
		{
			vulnerabilityType: vulnerability.Debian,
			sarifRuleName:     "OsPackageVulnerability",
		},
		{
			vulnerabilityType: vulnerability.DebianOVAL,
			sarifRuleName:     "OsPackageVulnerability",
		},
		{
			vulnerabilityType: vulnerability.Fedora,
			sarifRuleName:     "OsPackageVulnerability",
		},
		{
			vulnerabilityType: vulnerability.Amazon,
			sarifRuleName:     "OsPackageVulnerability",
		},
		{
			vulnerabilityType: vulnerability.OracleOVAL,
			sarifRuleName:     "OsPackageVulnerability",
		},
		{
			vulnerabilityType: vulnerability.SuseCVRF,
			sarifRuleName:     "OsPackageVulnerability",
		},
		{
			vulnerabilityType: vulnerability.OpenSuseCVRF,
			sarifRuleName:     "OsPackageVulnerability",
		},
		{
			vulnerabilityType: vulnerability.Photon,
			sarifRuleName:     "OsPackageVulnerability",
		},
		{
			vulnerabilityType: vulnerability.CentOS,
			sarifRuleName:     "OsPackageVulnerability",
		},
		{
			vulnerabilityType: vulnerability.Alma,
			sarifRuleName:     "OsPackageVulnerability",
		},
		{
			vulnerabilityType: "npm",
			sarifRuleName:     "ProgrammingLanguageVulnerability",
		},
		{
			vulnerabilityType: "yarn",
			sarifRuleName:     "ProgrammingLanguageVulnerability",
		},
		{
			vulnerabilityType: "nuget",
			sarifRuleName:     "ProgrammingLanguageVulnerability",
		},
		{
			vulnerabilityType: "pipenv",
			sarifRuleName:     "ProgrammingLanguageVulnerability",
		},
		{
			vulnerabilityType: "poetry",
			sarifRuleName:     "ProgrammingLanguageVulnerability",
		},
		{
			vulnerabilityType: "bundler",
			sarifRuleName:     "ProgrammingLanguageVulnerability",
		},
		{
			vulnerabilityType: "cargo",
			sarifRuleName:     "ProgrammingLanguageVulnerability",
		},
		{
			vulnerabilityType: "composer",
			sarifRuleName:     "ProgrammingLanguageVulnerability",
		},
		{
			vulnerabilityType: "redis",
			sarifRuleName:     "OtherVulnerability",
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
