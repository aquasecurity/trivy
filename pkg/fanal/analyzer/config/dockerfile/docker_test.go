package dockerfile

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_dockerConfigAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/Dockerfile.deployment",
			want: &analyzer.AnalysisResult{
				Files: map[types.HandlerType][]types.File{
					types.MisconfPostHandler: {
						{
							Type:    types.Dockerfile,
							Path:    "testdata/Dockerfile.deployment",
							Content: []byte(`FROM scratch`),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader("FROM scratch")
			a := dockerConfigAnalyzer{}
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

func Test_dockerConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "dockerfile",
			filePath: "dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile",
			filePath: "Dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile with ext",
			filePath: "Dockerfile.build",
			want:     true,
		},
		{
			name:     "dockerfile as ext",
			filePath: "build.dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile in dir",
			filePath: "docker/Dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile as prefix",
			filePath: "Dockerfilebuild",
			want:     false,
		},
		{
			name:     "Dockerfile as suffix",
			filePath: "buildDockerfile",
			want:     false,
		},
		{
			name:     "Dockerfile as prefix with ext",
			filePath: "Dockerfilebuild.sh",
			want:     false,
		},
		{
			name:     "Dockerfile as suffix with ext",
			filePath: "buildDockerfile.sh",
			want:     false,
		},
		{
			name:     "json",
			filePath: "deployment.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := dockerConfigAnalyzer{}
			got := s.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_dockerConfigAnalyzer_Type(t *testing.T) {
	s := dockerConfigAnalyzer{}
	want := analyzer.TypeDockerfile
	got := s.Type()
	assert.Equal(t, want, got)
}
