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

func Test_contentManifestAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *analyzer.AnalysisResult
		wantErr string
	}{
		{
			name:  "happy path",
			input: "testdata/content_manifests/ubi8-minimal-container-8.5-218.json",
			want: &analyzer.AnalysisResult{
				BuildInfo: &types.BuildInfo{
					ContentSets: []string{
						"rhel-8-for-x86_64-baseos-rpms",
						"rhel-8-for-x86_64-appstream-rpms",
					},
				},
			},
		},
		{
			name:    "broken json",
			input:   "testdata/content_manifests/broken.json",
			wantErr: "invalid content manifest",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.input)
			require.NoError(t, err)
			defer f.Close()

			a := contentManifestAnalyzer{}
			got, err := a.Analyze(context.Background(), analyzer.AnalysisInput{
				FilePath: tt.input,
				Content:  f,
			})

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_contentManifestAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "root/buildinfo/content_manifests/nodejs-12-container-1-66.json",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "root/buildinfo/content_manifests/nodejs-12-container-1-66.xml",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := contentManifestAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
