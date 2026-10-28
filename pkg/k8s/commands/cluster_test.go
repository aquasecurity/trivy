package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/flag"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestNormalizeComplianceReportFormat(t *testing.T) {
	tests := []struct {
		name       string
		compliance string
		format     types.Format
		report     string
		wantReport string
		wantChange bool
	}{
		{
			name:       "compliance table with all report",
			compliance: "k8s-cis",
			format:     types.FormatTable,
			report:     "all",
			wantReport: "summary",
			wantChange: true,
		},
		{
			name:       "compliance JSON with all report",
			compliance: "k8s-cis",
			format:     types.FormatJSON,
			report:     "all",
			wantReport: "all",
		},
		{
			name:       "table without compliance",
			format:     types.FormatTable,
			report:     "all",
			wantReport: "all",
		},
		{
			name:       "compliance table with summary report",
			compliance: "k8s-cis",
			format:     types.FormatTable,
			report:     "summary",
			wantReport: "summary",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := flag.Options{
				ReportOptions: flag.ReportOptions{
					Format:       tt.format,
					ReportFormat: tt.report,
					Compliance: spec.ComplianceSpec{
						Spec: iacTypes.Spec{ID: tt.compliance},
					},
				},
			}

			changed := normalizeComplianceReportFormat(&opts)

			assert.Equal(t, tt.wantChange, changed)
			assert.Equal(t, tt.wantReport, opts.ReportFormat)
		})
	}
}
