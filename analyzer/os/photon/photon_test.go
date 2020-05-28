package photon

import (
	"io/ioutil"
	"testing"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
)

func Test_photonOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      analyzer.AnalyzeReturn
		wantErr   string
	}{
		{
			name:      "happy path with Photon OS 3.0",
			inputFile: "testdata/photon_3/os-release",
			want: analyzer.AnalyzeReturn{
				OS: types.OS{Family: os.Photon, Name: "3.0"},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/not_photon/os-release",
			want: analyzer.AnalyzeReturn{
				OS: types.OS{Family: os.Photon, Name: "3.0"},
			},
			wantErr: "photon: unable to analyze OS information",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := photonOSAnalyzer{}
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
