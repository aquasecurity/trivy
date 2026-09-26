package report

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestTemplateWriter_Write(t *testing.T) {
	report := Report{
		Resources: []Resource{{
			Kind: "Pod",
			Name: "nginx",
			Results: types.Results{{
				Misconfigurations: []types.DetectedMisconfiguration{{}},
			}},
		}},
	}

	tests := []struct {
		name       string
		reportType string
		template   string
		want       string
		wantErr    string
	}{
		{
			name:       "all resources",
			reportType: AllReport,
			template:   `{{ range .Resources }}{{ .Kind }}/{{ .Name }} {{ end }}`,
			want:       "Pod/nginx ",
		},
		{
			name:       "summary consolidates findings",
			reportType: SummaryReport,
			template:   `{{ range .Findings }}{{ .Kind }}/{{ .Name }}{{ end }}`,
			want:       "Pod/nginx",
		},
		{
			name:       "unsupported report type",
			reportType: "custom",
			template:   `{{ . }}`,
			wantErr:    `report "custom" not supported. Use "summary" or "all"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			writer := TemplateWriter{
				Output:   &output,
				Report:   tt.reportType,
				Template: tt.template,
			}

			err := writer.Write(report)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, output.String())
		})
	}
}
