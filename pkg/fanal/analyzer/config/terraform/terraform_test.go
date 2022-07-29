package terraform_test

import (
	"bytes"
	"context"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/terraform"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_TerraformConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name  string
		input analyzer.AnalysisInput
		want  *analyzer.AnalysisResult
	}{
		{
			name: "happy path1",
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
		{
			name: "happy path2",
			input: analyzer.AnalysisInput{
				Dir:      "path/to/",
				FilePath: "main.tf.json",
				Content:  bytes.NewReader(nil),
			},
			want: &analyzer.AnalysisResult{
				Files: map[types.HandlerType][]types.File{
					types.MisconfPostHandler: {
						{
							Type:    types.Terraform,
							Path:    "main.tf.json",
							Content: []byte{},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := terraform.NewConfigAnalyzer(nil)
			ctx := context.Background()
			got, err := a.Analyze(ctx, tt.input)

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_TerraformConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name        string
		filePattern *regexp.Regexp
		filePath    string
		want        bool
	}{
		{
			name:     "happy path1",
			filePath: "/path/to/main.tf",
			want:     true,
		},
		{
			name:     "happy path2",
			filePath: "/path/to/main.tf.json",
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
		{
			name:        "file pattern",
			filePattern: regexp.MustCompile(`foo*`),
			filePath:    "foo_file",
			want:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := terraform.NewConfigAnalyzer(tt.filePattern)
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_TerraformConfigAnalyzer_Type(t *testing.T) {
	a := terraform.NewConfigAnalyzer(nil)
	want := analyzer.TypeTerraform
	got := a.Type()
	assert.Equal(t, want, got)
}
