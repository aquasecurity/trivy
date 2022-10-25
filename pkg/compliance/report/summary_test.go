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
						ControlCheckID:  "1.0",
						ControlName:     "Non-root containers",
						ControlSeverity: "MEDIUM",
						Results: types.Results{
							{
								Misconfigurations: []types.DetectedMisconfiguration{
									{AVDID: "AVD-KSV012", Status: types.StatusFailure},
								},
							},
						},
					},
					{
						ControlCheckID:  "1.1",
						ControlName:     "Immutable container file systems",
						ControlSeverity: "LOW",
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
				ReportID:      "1234",
				ReportTitle:   "NSA",
				SummaryControls: []report.ControlCheckSummary{
					{
						ControlCheckID:  "1.0",
						ControlName:     "Non-root containers",
						ControlSeverity: "MEDIUM",
						TotalPass:       0,
						TotalFail:       1,
					},
					{
						ControlCheckID:  "1.1",
						ControlName:     "Immutable container file systems",
						ControlSeverity: "LOW",
						TotalPass:       0,
						TotalFail:       1,
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
						ControlCheckID:  "1.0",
						ControlName:     "Non-root containers",
						ControlSeverity: "MEDIUM",
						Results: types.Results{
							{
								Misconfigurations: []types.DetectedMisconfiguration{
									{AVDID: "AVD-KSV012", Status: types.StatusFailure},
								},
							},
						},
					},
					{
						ControlCheckID:  "1.1",
						ControlName:     "Immutable container file systems",
						ControlSeverity: "LOW",
						Results: types.Results{
							{
								Misconfigurations: []types.DetectedMisconfiguration{
									{AVDID: "AVD-KSV013", Status: types.StatusFailure},
								},
							},
						},
					},
					{
						ControlCheckID:  "1.2",
						ControlName:     "tzdata - new upstream version",
						ControlSeverity: "LOW",
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
				ReportID:      "1234",
				ReportTitle:   "NSA",
				SummaryControls: []report.ControlCheckSummary{
					{
						ControlCheckID:  "1.0",
						ControlName:     "Non-root containers",
						ControlSeverity: "MEDIUM",
						TotalPass:       0,
						TotalFail:       1,
					},
					{
						ControlCheckID:  "1.1",
						ControlName:     "Immutable container file systems",
						ControlSeverity: "LOW",
						TotalPass:       0,
						TotalFail:       1,
					},
					{
						ControlCheckID:  "1.2",
						ControlName:     "tzdata - new upstream version",
						ControlSeverity: "LOW",
						TotalPass:       0,
						TotalFail:       2,
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
