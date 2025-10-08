package report_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/compliance/report"
	compliance "github.com/aquasecurity/trivy/pkg/compliance/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestTableWriter_Write(t *testing.T) {

	tests := []struct {
		name       string
		reportType string
		input      *compliance.Report
		want       string
	}{
		{
			name:       "build summary table",
			reportType: "summary",
			input: &compliance.Report{
				ID:               "1234",
				Title:            "NSA",
				RelatedResources: []string{"https://example.com"},
				Results: []*compliance.ControlCheckResult{
					{
						ID:       "1.0",
						Name:     "Non-root containers",
						Severity: "MEDIUM",
						Results: types.Results{
							{
								Misconfigurations: []types.DetectedMisconfiguration{
									{
										AVDID:  "AVD-KSV012",
										Status: types.MisconfStatusFailure,
									},
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
									{
										AVDID:  "AVD-KSV013",
										Status: types.MisconfStatusFailure,
									},
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
			tr := report.TableWriter{
				Report: tt.reportType,
				Output: buf,
			}
			err := tr.Write(t.Context(), tt.input)
			require.NoError(t, err)

			want, err := os.ReadFile(tt.want)
			want = bytes.ReplaceAll(want, []byte("\r"), []byte(""))

			require.NoError(t, err)

			assert.Equal(t, string(want), buf.String())
		})
	}
}
