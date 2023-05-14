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

func Test_centosOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/centos/centos-release",
			want: &analyzer.AnalysisResult{
				OS: types.OS{Family: "centos", Name: "7.6.1810"},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/not_redhatbase/empty",
			wantErr:   "centos: unable to analyze OS information",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := centOSAnalyzer{}
			f, err := os.Open(tt.inputFile)
			defer f.Close()

			require.NoError(t, err)
			ctx := context.Background()

			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: "etc/centos-release",
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
