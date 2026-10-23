package release

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/debian"
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
			name:      "ActiveState",
			inputFile: "testdata/activestate",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.ActiveState,
					Name:   "1.0",
				},
			},
		},
		{
			name:      "Fedora",
			inputFile: "testdata/fedora",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Fedora,
					Name:   "42",
				},
			},
		},
		{
			name:      "Ubuntu",
			inputFile: "testdata/ubuntu",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Ubuntu,
					Name:   "26.10",
				},
			},
		},
		{
			name:      "Red Hat Enterprise Linux",
			inputFile: "testdata/rhel",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.RedHat,
					Name:   "9.4",
				},
			},
		},
		{
			name:      "CentOS",
			inputFile: "testdata/centos",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.CentOS,
					Name:   "7",
				},
			},
		},
		{
			name:      "CentOS Stream",
			inputFile: "testdata/centos-stream",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.CentOSStream,
					Name:   "8",
				},
			},
		},
		{
			name:      "Rocky Linux",
			inputFile: "testdata/rocky",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Rocky,
					Name:   "9.3",
				},
			},
		},
		{
			name:      "AlmaLinux",
			inputFile: "testdata/alma",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Alma,
					Name:   "9.4",
				},
			},
		},
		{
			name:      "Oracle Linux",
			inputFile: "testdata/oracle",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Oracle,
					Name:   "8.10",
				},
			},
		},
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
			name:      "Echo",
			inputFile: "testdata/echo",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Echo,
					Name:   "1",
				},
			},
		},
		{
			name:      "MinimOS",
			inputFile: "testdata/minimos",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.MinimOS,
					Name:   "20241031",
				},
			},
		},
		{
			name:      "Bottlerocket",
			inputFile: "testdata/bottlerocket",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Bottlerocket,
					Name:   "1.34.0",
				},
			},
		},
		{
			name:      "CoreOS",
			inputFile: "testdata/coreos",
			want: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.CoreOS,
					Name:   "3.15.4",
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
			res, err := a.Analyze(t.Context(), analyzer.AnalysisInput{
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

func TestUbuntuWithDebianVersion(t *testing.T) {
	osRelease, err := os.ReadFile("testdata/ubuntu")
	require.NoError(t, err)
	info, err := os.Stat("testdata/ubuntu")
	require.NoError(t, err)
	group, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{})
	require.NoError(t, err)

	for _, path := range []string{"etc/os-release", "usr/lib/os-release"} {
		files := map[string]string{
			path:                 string(osRelease),
			"etc/debian_version": "forky/sid\n",
		}
		for _, paths := range [][]string{{path, "etc/debian_version"}, {"etc/debian_version", path}} {
			t.Run(strings.Join(paths, ","), func(t *testing.T) {
				result := new(analyzer.AnalysisResult)
				for _, filePath := range paths {
					eg, ctx := errgroup.WithContext(t.Context())
					err := group.AnalyzeFile(ctx, eg, semaphore.NewWeighted(1), result, "", filePath, info,
						func() (xio.ReadSeekCloserAt, error) {
							return xio.NopCloser(strings.NewReader(files[filePath])), nil
						}, nil, analyzer.AnalysisOptions{})
					require.NoError(t, err)
					// Complete each file's analysis to exercise both merge orders.
					require.NoError(t, eg.Wait())
				}
				assert.Equal(t, types.OS{Family: types.Ubuntu, Name: "26.10"}, result.OS)
			})
		}
	}
}
