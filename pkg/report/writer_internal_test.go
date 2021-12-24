package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReportWriter_toSarifRuleName(t *testing.T) {
	tests := []struct {
		resourceClass string
		sarifRuleName string
	}{
		{
			resourceClass: "os-pkgs",
			sarifRuleName: sarifOsPackageVulnerability,
		},
		{
			resourceClass: "lang-pkgs",
			sarifRuleName: sarifLanguageSpecificVulnerability,
		},
		{
			resourceClass: "config",
			sarifRuleName: sarifConfigFiles,
		},
		{
			resourceClass: "redis",
			sarifRuleName: sarifUnknownIssue,
		},
	}
	for _, tc := range tests {
		t.Run(tc.resourceClass, func(t *testing.T) {
			assert.Equal(t, tc.sarifRuleName, toSarifRuleName(tc.resourceClass), tc.resourceClass)
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
