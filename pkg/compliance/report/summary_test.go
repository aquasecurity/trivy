package report_test

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/compliance/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildSummary(t *testing.T) {
	tests := []struct {
		name       string
		reportType string
		input      *report.ComplianceReport
		want       *report.SummaryReport
	}{
		{
			name:       "build report summary config only",
			reportType: "summary",
			input: &report.ComplianceReport{
				ID:               "1234",
				Title:            "NSA",
				RelatedResources: []string{"https://example.com"},
				Results: []*report.ControlCheckResult{
					{
						ID:       "1.0",
						Name:     "Non-root containers",
						Severity: "MEDIUM",
						Results: types.Results{
							{
								Misconfigurations: []types.DetectedMisconfiguration{
									{AVDID: "AVD-KSV012", Status: types.StatusFailure},
								},
							},
						},
					},
					{
						ID:       "1.1",
						Name:     "Immutable container file systems",
						Severity: "LOW",
						Results: types.Results{
							{
								Misconfigurations: []types.DetectedMisconfiguration{
									{AVDID: "AVD-KSV013", Status: types.StatusFailure},
								},
							},
						},
					},
				},
			},
			want: &report.SummaryReport{
				SchemaVersion: 0,
				ID:            "1234",
				Title:         "NSA",
				SummaryControls: []report.ControlCheckSummary{
					{
						ID:        "1.0",
						Name:      "Non-root containers",
						Severity:  "MEDIUM",
						TotalPass: 0,
						TotalFail: 1,
					},
					{
						ID:        "1.1",
						Name:      "Immutable container file systems",
						Severity:  "LOW",
						TotalPass: 0,
						TotalFail: 1,
					},
				},
			},
		},
		{
			name:       "build full json output report",
			reportType: "all",
			input: &report.ComplianceReport{
				ID:               "1234",
				Title:            "NSA",
				RelatedResources: []string{"https://example.com"},
				Results: []*report.ControlCheckResult{
					{
						ID:       "1.0",
						Name:     "Non-root containers",
						Severity: "MEDIUM",
						Results: types.Results{
							{
								Misconfigurations: []types.DetectedMisconfiguration{
									{AVDID: "AVD-KSV012", Status: types.StatusFailure},
								},
							},
						},
					},
					{
						ID:       "1.1",
						Name:     "Immutable container file systems",
						Severity: "LOW",
						Results: types.Results{
							{
								Misconfigurations: []types.DetectedMisconfiguration{
									{AVDID: "AVD-KSV013", Status: types.StatusFailure},
								},
							},
						},
					},
					{
						ID:       "1.2",
						Name:     "tzdata - new upstream version",
						Severity: "LOW",
						Results: types.Results{
							{
								Vulnerabilities: []types.DetectedVulnerability{
									{VulnerabilityID: "CVE-9999-0001"},
									{VulnerabilityID: "CVE-9999-0002"},
								},
							},
						},
					},
				},
			},
			want: &report.SummaryReport{
				SchemaVersion: 0,
				ID:            "1234",
				Title:         "NSA",
				SummaryControls: []report.ControlCheckSummary{
					{
						ID:        "1.0",
						Name:      "Non-root containers",
						Severity:  "MEDIUM",
						TotalPass: 0,
						TotalFail: 1,
					},
					{
						ID:        "1.1",
						Name:      "Immutable container file systems",
						Severity:  "LOW",
						TotalPass: 0,
						TotalFail: 1,
					},
					{
						ID:        "1.2",
						Name:      "tzdata - new upstream version",
						Severity:  "LOW",
						TotalPass: 0,
						TotalFail: 2,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := report.BuildSummary(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}
