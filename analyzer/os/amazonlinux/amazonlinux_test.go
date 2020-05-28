package amazonlinux

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/fanal/analyzer"
)

func Test_amazonlinuxOSAnalyzer_Analyze(t *testing.T) {
	type args struct {
		content []byte
	}
	tests := []struct {
		name    string
		args    args
		want    analyzer.AnalyzeReturn
		wantErr string
	}{
		{
			name: "happy path amazon linux 1",
			args: args{
				content: []byte(`Amazon Linux AMI release 2018.03`),
			},
			want: analyzer.AnalyzeReturn{
				OS: types.OS{
					Family: aos.Amazon,
					Name:   "AMI release 2018.03",
				},
			},
		},
		{
			name: "happy path amazon linux 2",
			args: args{
				content: []byte(`Amazon Linux release 2 (Karoo)`),
			},
			want: analyzer.AnalyzeReturn{
				OS: types.OS{
					Family: aos.Amazon,
					Name:   "2 (Karoo)",
				},
			},
		},
		{
			name: "sad path amazon linux 2 without code name",
			args: args{
				content: []byte(`Amazon Linux release 2`),
			},
			wantErr: aos.AnalyzeOSError.Error(),
		},
		{
			name: "sad path",
			args: args{
				content: []byte(`foo bar`),
			},
			wantErr: aos.AnalyzeOSError.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := amazonlinuxOSAnalyzer{}
			got, err := a.Analyze(tt.args.content)
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
