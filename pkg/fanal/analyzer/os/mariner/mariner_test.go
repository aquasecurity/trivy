package mariner

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_marinerOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path with CBL Mariner 1.0",
			inputFile: "testdata/1.0/mariner-release",
			want: &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: aos.CBLMariner,
					Name:   "1.0.20220122",
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/sad/mariner-release",
			wantErr:   "cbl-mariner: unable to analyze OS information",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := marinerOSAnalyzer{}
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: "etc/mariner-release",
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
