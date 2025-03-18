package debian

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_debianOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path with debian 9",
			inputFile: "testdata/debian_9/etc/debian_version",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Debian,
					Name:   "9.8",
				},
			},
		},
		{
			name:      "happy path with debian sid",
			inputFile: "testdata/debian_sid/etc/debian_version",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Debian,
					Name:   "buster/sid",
				},
			},
		},
		{
			name:      "sad path with empty file",
			inputFile: "testdata/empty",
			wantErr:   "debian: unable to analyze OS information",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := debianOSAnalyzer{}
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			ctx := t.Context()

			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: "etc/debian_version",
				Content:  f,
			})
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
