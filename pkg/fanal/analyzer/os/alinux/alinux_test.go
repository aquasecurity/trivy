package alinux

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_alinuxOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		input   analyzer.AnalysisInput
		want    *analyzer.AnalysisResult
		wantErr string
	}{
		{
			name: "happy path alinux 2",
			input: analyzer.AnalysisInput{
				FilePath: "etc/alinux-release",
				Content:  strings.NewReader("Alibaba Cloud Linux release 2.1903 LTS (Hunting Beagle)"),
			},
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Alinux,
					Name:   "2.1903",
				},
			},
		},
		{
			name: "happy path alinux 3",
			input: analyzer.AnalysisInput{
				FilePath: "etc/alinux-release",
				Content:  strings.NewReader("Alibaba Cloud Linux release 3 (Soaring Falcon)"),
			},
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Alinux,
					Name:   "3",
				},
			},
		},
		{
			name: "happy path alinux 4",
			input: analyzer.AnalysisInput{
				FilePath: "etc/system-release",
				Content:  strings.NewReader("Alibaba Cloud Linux release 4.0"),
			},
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Alinux,
					Name:   "4.0",
				},
			},
		},
		{
			name: "sad path",
			input: analyzer.AnalysisInput{
				FilePath: "etc/alinux-release",
				Content:  strings.NewReader("foo bar"),
			},
			wantErr: fos.AnalyzeOSError.Error(),
		},
		{
			name: "sad path empty",
			input: analyzer.AnalysisInput{
				FilePath: "etc/alinux-release",
				Content:  strings.NewReader(""),
			},
			wantErr: fos.AnalyzeOSError.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := alinuxOSAnalyzer{}
			ctx := t.Context()
			got, err := a.Analyze(ctx, tt.input)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
