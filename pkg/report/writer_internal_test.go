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
			sarifRuleName:     "OS Package Vulnerability",
		},
		{
			vulnerabilityType: vulnerability.Alpine,
			sarifRuleName:     "OS Package Vulnerability",
		},
		{
			vulnerabilityType: vulnerability.RedHat,
			sarifRuleName:     "OS Package Vulnerability",
		},
		{
			vulnerabilityType: vulnerability.RedHatOVAL,
			sarifRuleName:     "OS Package Vulnerability",
		},
		{
			vulnerabilityType: vulnerability.Debian,
			sarifRuleName:     "OS Package Vulnerability",
		},
		{
			vulnerabilityType: vulnerability.DebianOVAL,
			sarifRuleName:     "OS Package Vulnerability",
		},
		{
			vulnerabilityType: vulnerability.Fedora,
			sarifRuleName:     "OS Package Vulnerability",
		},
		{
			vulnerabilityType: vulnerability.Amazon,
			sarifRuleName:     "OS Package Vulnerability",
		},
		{
			vulnerabilityType: vulnerability.OracleOVAL,
			sarifRuleName:     "OS Package Vulnerability",
		},
		{
			vulnerabilityType: vulnerability.SuseCVRF,
			sarifRuleName:     "OS Package Vulnerability",
		},
		{
			vulnerabilityType: vulnerability.OpenSuseCVRF,
			sarifRuleName:     "OS Package Vulnerability",
		},
		{
			vulnerabilityType: vulnerability.Photon,
			sarifRuleName:     "OS Package Vulnerability",
		},
		{
			vulnerabilityType: vulnerability.CentOS,
			sarifRuleName:     "OS Package Vulnerability",
		},
		{
			vulnerabilityType: "npm",
			sarifRuleName:     "Programming Language Vulnerability",
		},
		{
			vulnerabilityType: "yarn",
			sarifRuleName:     "Programming Language Vulnerability",
		},
		{
			vulnerabilityType: "nuget",
			sarifRuleName:     "Programming Language Vulnerability",
		},
		{
			vulnerabilityType: "pipenv",
			sarifRuleName:     "Programming Language Vulnerability",
		},
		{
			vulnerabilityType: "poetry",
			sarifRuleName:     "Programming Language Vulnerability",
		},
		{
			vulnerabilityType: "bundler",
			sarifRuleName:     "Programming Language Vulnerability",
		},
		{
			vulnerabilityType: "cargo",
			sarifRuleName:     "Programming Language Vulnerability",
		},
		{
			vulnerabilityType: "composer",
			sarifRuleName:     "Programming Language Vulnerability",
		},
		{
			vulnerabilityType: "redis",
			sarifRuleName:     "Other Vulnerability",
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
