package report_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy/pkg/compliance/report"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestJSONWriter_Write(t *testing.T) {
	input := &report.ComplianceReport{
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
	}

	tests := []struct {
		name       string
		reportType string
		input      *report.ComplianceReport
		want       string
	}{
		{
			name:       "build summary json output report",
			reportType: "summary",
			input:      input,
			want:       filepath.Join("testdata", "summary.json"),
		},
		{
			name:       "build full json output report",
			reportType: "all",
			input:      input,
			want:       filepath.Join("testdata", "all.json"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			tr := report.JSONWriter{Report: tt.reportType, Output: buf}
			err := tr.Write(tt.input)
			require.NoError(t, err)

			want, err := os.ReadFile(tt.want)
			require.NoError(t, err)

			assert.JSONEq(t, string(want), buf.String())
		})
	}
}
