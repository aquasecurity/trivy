package redhatbase

import (
	"io/ioutil"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_oracleOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      analyzer.AnalyzeReturn
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/oracle_7/oracle-release",
			want: analyzer.AnalyzeReturn{
				OS: types.OS{Family: "oracle", Name: "7.6"},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/not_redhatbase/empty",
			wantErr:   "oracle: unable to analyze OS information",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := oracleOSAnalyzer{}
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			got, err := a.Analyze(b)
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
