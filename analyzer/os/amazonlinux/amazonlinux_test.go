package amazonlinux

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/fanal/analyzer"
)

func Test_amazonlinuxOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		target  analyzer.AnalysisTarget
		want    *analyzer.AnalysisResult
		wantErr string
	}{
		{
			name: "happy path amazon linux 1",
			target: analyzer.AnalysisTarget{
				FilePath: "etc/system-release",
				Content:  []byte(`Amazon Linux AMI release 2018.03`),
			},
			want: &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: aos.Amazon,
					Name:   "AMI release 2018.03",
				},
			},
		},
		{
			name: "happy path amazon linux 2",
			target: analyzer.AnalysisTarget{
				FilePath: "etc/system-release",
				Content:  []byte(`Amazon Linux release 2 (Karoo)`),
			},
			want: &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: aos.Amazon,
					Name:   "2 (Karoo)",
				},
			},
		},
		{
			name: "sad path amazon linux 2 without code name",
			target: analyzer.AnalysisTarget{
				FilePath: "etc/system-release",
				Content:  []byte(`Amazon Linux release 2`),
			},
			wantErr: aos.AnalyzeOSError.Error(),
		},
		{
			name: "sad path",
			target: analyzer.AnalysisTarget{
				FilePath: "etc/system-release",
				Content:  []byte(`foo bar`),
			},
			wantErr: aos.AnalyzeOSError.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := amazonlinuxOSAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, tt.target)
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
