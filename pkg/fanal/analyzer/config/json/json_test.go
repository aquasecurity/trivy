package json

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_jsonConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "test.json",
			want: &analyzer.AnalysisResult{
				Files: map[types.HandlerType][]types.File{
					types.MisconfPostHandler: {
						{
							Type:    "json",
							Path:    "test.json",
							Content: []byte(`{}`),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader("{}")

			s := jsonConfigAnalyzer{}
			got, err := s.Analyze(context.Background(), analyzer.AnalysisInput{
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

func Test_jsonConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "json",
			filePath: "deployment.json",
			want:     true,
		},
		{
			name:     "yaml",
			filePath: "deployment.yaml",
			want:     false,
		},
		{
			name:     "npm json",
			filePath: "package-lock.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := jsonConfigAnalyzer{}

			got := s.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_jsonConfigAnalyzer_Type(t *testing.T) {
	s := jsonConfigAnalyzer{}

	want := analyzer.TypeJSON
	got := s.Type()
	assert.Equal(t, want, got)
}
