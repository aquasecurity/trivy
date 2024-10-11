package release

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_osReleaseAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		input     analyzer.AnalysisInput
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "alpine",
			inputFile: "testdata/alpine",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Alpine,
					Name:   "3.15.4",
				},
			},
		},
		{
			name:      "openSUSE-leap 15.2.1",
			inputFile: "testdata/opensuseleap-15.2.1",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.OpenSUSELeap,
					Name:   "15.2.1",
				},
			},
		},
		{
			name:      "openSUSE-leap 42.3",
			inputFile: "testdata/opensuseleap-42.3",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.OpenSUSELeap,
					Name:   "42.3",
				},
			},
		},
		{
			name:      "openSUSE-tumbleweed",
			inputFile: "testdata/opensusetumbleweed",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.OpenSUSETumbleweed,
					Name:   "20220412",
				},
			},
		},
		{
			name:      "SUSE Linux Enterprise Server",
			inputFile: "testdata/sles",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.SLES,
					Name:   "15.3",
				},
			},
		},
		{
			name:      "SUSE Linux Enterprise Micro",
			inputFile: "testdata/slemicro",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.SLEMicro,
					Name:   "5.3",
				},
			},
		},
		{
			name:      "SUSE Linux Enterprise Micro 6.0",
			inputFile: "testdata/slemicro6.0",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.SLEMicro,
					Name:   "6.0",
				},
			},
		},
		{
			name:      "SUSE Linux Enterprise Micro 5.4 for Rancher",
			inputFile: "testdata/slemicro-rancher",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.SLEMicro,
					Name:   "5.4",
				},
			},
		},
		{
			name:      "Photon OS",
			inputFile: "testdata/photon",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Photon,
					Name:   "4.0",
				},
			},
		},
		{
			name:      "Photon OS",
			inputFile: "testdata/photon",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Photon,
					Name:   "4.0",
				},
			},
		},
		{
			name:      "Azure Linux",
			inputFile: "testdata/azurelinux-3.0",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Azure,
					Name:   "3.0",
				},
			},
		},
		{
			name:      "Mariner 2.0",
			inputFile: "testdata/mariner-2.0",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.CBLMariner,
					Name:   "2.0",
				},
			},
		},
		{
			name:      "Mariner 1.0",
			inputFile: "testdata/mariner-1.0",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.CBLMariner,
					Name:   "1.0",
				},
			},
		},
		{
			name:      "Unknown OS",
			inputFile: "testdata/unknown",
			want:      nil,
		},
		{
			name:      "No 'ID' field",
			inputFile: "testdata/no-id",
			want:      nil,
		},
		{
			name:      "No 'VERSION_ID' field",
			inputFile: "testdata/no-version",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := osReleaseAnalyzer{}
			res, err := a.Analyze(context.Background(), analyzer.AnalysisInput{
				FilePath: "etc/os-release",
				Content:  f,
			})

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err.Error())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, res)
		})
	}
}
