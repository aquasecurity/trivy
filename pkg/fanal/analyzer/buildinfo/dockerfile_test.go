package buildinfo

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_dockerfileAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "com.redhat.component",
			inputFile: "testdata/dockerfile/Dockerfile-ubi8-8.3-227",
			want: &analyzer.AnalysisResult{
				BuildInfo: &types.BuildInfo{
					Nvr:  "ubi8-container-8.3-227",
					Arch: "x86_64",
				},
			},
		},
		{
			name:      "BZcomponent",
			inputFile: "testdata/dockerfile/Dockerfile-jboss-base-7-base-1.1-3",
			want: &analyzer.AnalysisResult{
				BuildInfo: &types.BuildInfo{
					Nvr:  "jboss-base-7-docker-1.1-3",
					Arch: "x86_64",
				},
			},
		},
		{
			name:      "missing architecture",
			inputFile: "testdata/dockerfile/Dockerfile.sad",
			wantErr:   "no arch found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := dockerfileAnalyzer{}
			got, err := a.Analyze(context.Background(), analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_dockerfileAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "root/buildinfo/Dockerfile-ubi8-8.3-227",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "app/Dockerfile-ubi8-8.3-227",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := dockerfileAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
