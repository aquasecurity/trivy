package redhatbase

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_rockyOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/rocky/rocky-release",
			want: &analyzer.AnalysisResult{
				OS: &types.OS{Family: "rocky", Name: "8.4"},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/not_redhatbase/empty",
			wantErr:   "rocky: unable to analyze OS information",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := rockyOSAnalyzer{}
			b, err := os.ReadFile(tt.inputFile)
			require.NoError(t, err)
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisTarget{
				FilePath: "etc/rocky-release",
				Content:  b,
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
