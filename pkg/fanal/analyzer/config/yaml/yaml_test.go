package yaml

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_yamlConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "test.yaml",
			want: &analyzer.AnalysisResult{
				Files: map[types.HandlerType][]types.File{
					types.MisconfPostHandler: {
						{
							Type:    "yaml",
							Path:    "test.yaml",
							Content: []byte(`- abc`),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader("- abc")
			a := yamlConfigAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  r,
			})

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_yamlConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "yaml",
			filePath: "deployment.yaml",
			want:     true,
		},
		{
			name:     "yml",
			filePath: "deployment.yml",
			want:     true,
		},
		{
			name:     "json",
			filePath: "deployment.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := yamlConfigAnalyzer{}

			got := s.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_yamlConfigAnalyzer_Type(t *testing.T) {
	s := yamlConfigAnalyzer{}

	want := analyzer.TypeYaml
	got := s.Type()
	assert.Equal(t, want, got)
}
