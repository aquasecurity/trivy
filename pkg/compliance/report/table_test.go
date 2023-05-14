package report_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/compliance/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestTableWriter_Write(t *testing.T) {

	tests := []struct {
		name       string
		reportType string
		input      *report.ComplianceReport
		want       string
	}{
		{
			name:       "build summary table",
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
			want: filepath.Join("testdata", "table_summary.txt"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			tr := report.TableWriter{Report: tt.reportType, Output: buf}
			err := tr.Write(tt.input)
			require.NoError(t, err)

			want, err := os.ReadFile(tt.want)
			want = bytes.ReplaceAll(want, []byte("\r"), []byte(""))

			require.NoError(t, err)

			assert.Equal(t, string(want), buf.String())
		})
	}
}
