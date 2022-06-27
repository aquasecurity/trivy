package ubuntu

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ubuntuOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		testFile string
		want     *analyzer.AnalysisResult
		wantErr  string
	}{
		{
			name:     "happy path. Parse lsb-release file",
			filePath: "testdata/lsb-release",
			testFile: "testdata/lsb-release",
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: "ubuntu", Name: "18.04"},
			},
		},
		{
			name:     "happy path. Parse status.json file(ESM enabled)",
			filePath: "var/lib/ubuntu-advantage/status.json",
			testFile: "testdata/esm_enabled_status.json",
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: "ubuntu", Extended: "ESM"},
			},
		},
		{
			name:     "happy path. Parse status.json file(ESM disabled)",
			filePath: "var/lib/ubuntu-advantage/status.json",
			testFile: "testdata/esm_disabled_status.json",
			want:     nil,
		},
		{
			name:     "sad path",
			filePath: "testdata/lsb-release",
			testFile: "testdata/invalid",
			wantErr:  "ubuntu: unable to analyze OS information",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := ubuntuOSAnalyzer{}
			f, err := os.Open(tt.testFile)
			require.NoError(t, err)
			defer f.Close()

			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.filePath,
				Content:  f,
			})
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_ubuntuOSAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path lsb-release",
			filePath: "etc/lsb-release",
			want:     true,
		},
		{
			name:     "happy path status.json",
			filePath: "var/lib/ubuntu-advantage/status.json",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "etc/invalid",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := ubuntuOSAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
