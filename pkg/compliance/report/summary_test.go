package report_test

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/compliance/report"
	"github.com/aquasecurity/trivy/pkg/types"
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
						TotalFail: lo.ToPtr(1),
					},
					{
						ID:        "1.1",
						Name:      "Immutable container file systems",
						Severity:  "LOW",
						TotalFail: lo.ToPtr(1),
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
						TotalFail: lo.ToPtr(1),
					},
					{
						ID:        "1.1",
						Name:      "Immutable container file systems",
						Severity:  "LOW",
						TotalFail: lo.ToPtr(1),
					},
					{
						ID:        "1.2",
						Name:      "tzdata - new upstream version",
						Severity:  "LOW",
						TotalFail: lo.ToPtr(1),
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
