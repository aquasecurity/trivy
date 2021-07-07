package terraform_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config/terraform"
	"github.com/aquasecurity/fanal/types"
)

func TestConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name   string
		target analyzer.AnalysisTarget
		want   *analyzer.AnalysisResult
	}{
		{
			name: "happy path",
			target: analyzer.AnalysisTarget{
				Dir:      "path/to/",
				FilePath: "main.tf",
			},
			want: &analyzer.AnalysisResult{
				Configs: []types.Config{
					{
						Type:     types.Terraform,
						FilePath: "path/to/main.tf",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := terraform.ConfigAnalyzer{}
			got, err := a.Analyze(tt.target)

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
