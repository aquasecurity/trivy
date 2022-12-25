package amazonlinux

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	aos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

func Test_amazonlinuxOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		input   analyzer.AnalysisInput
		want    *analyzer.AnalysisResult
		wantErr string
	}{
		{
			name: "happy path amazon linux 1",
			input: analyzer.AnalysisInput{
				FilePath: "etc/system-release",
				Content:  strings.NewReader(`Amazon Linux AMI release 2018.03`),
			},
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: aos.Amazon,
					Name:   "AMI release 2018.03",
				},
			},
		},
		{
			name: "happy path amazon linux 2",
			input: analyzer.AnalysisInput{
				FilePath: "etc/system-release",
				Content:  strings.NewReader(`Amazon Linux release 2 (Karoo)`),
			},
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: aos.Amazon,
					Name:   "2 (Karoo)",
				},
			},
		},
		{
			name: "happy path amazon linux 2022",
			input: analyzer.AnalysisInput{
				FilePath: "usr/lib/system-release",
				Content:  strings.NewReader(`Amazon Linux release 2022 (Amazon Linux)`),
			},
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: aos.Amazon,
					Name:   "2022 (Amazon Linux)",
				},
			},
		},
		{
			name: "sad path amazon linux 2 without code name",
			input: analyzer.AnalysisInput{
				FilePath: "etc/system-release",
				Content:  strings.NewReader(`Amazon Linux release 2`),
			},
			wantErr: aos.AnalyzeOSError.Error(),
		},
		{
			name: "sad path",
			input: analyzer.AnalysisInput{
				FilePath: "etc/system-release",
				Content:  strings.NewReader(`foo bar`),
			},
			wantErr: aos.AnalyzeOSError.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := amazonlinuxOSAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, tt.input)
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
