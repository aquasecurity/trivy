package redhatbase

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_almaOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/alma/almalinux-release",
			want: &analyzer.AnalysisResult{
				OS: types.OS{Family: "alma", Name: "8.4"},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/not_redhatbase/empty",
			wantErr:   "alma: unable to analyze OS information",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := almaOSAnalyzer{}
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			ctx := context.Background()

			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: "etc/almalinux-release",
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
