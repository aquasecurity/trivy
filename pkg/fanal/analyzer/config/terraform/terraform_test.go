package terraform_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/terraform"
	"github.com/aquasecurity/fanal/types"
)

func TestConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name  string
		input analyzer.AnalysisInput
		want  *analyzer.AnalysisResult
	}{
		{
			name: "happy path",
			input: analyzer.AnalysisInput{
				Dir:      "path/to/",
				FilePath: "main.tf",
				Content:  bytes.NewReader(nil),
			},
			want: &analyzer.AnalysisResult{
				Files: map[types.HandlerType][]types.File{
					types.MisconfPostHandler: {
						{
							Type:    types.Terraform,
							Path:    "main.tf",
							Content: []byte{},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := terraform.ConfigAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, tt.input)

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "/path/to/main.tf",
			want:     true,
		},
		{
			name:     "hcl",
			filePath: "/path/to/main.hcl",
			want:     false,
		},
		{
			name:     "yaml",
			filePath: "deployment.yaml",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := terraform.ConfigAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
