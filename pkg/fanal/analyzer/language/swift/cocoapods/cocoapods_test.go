package cocoapods

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_cocoaPodsLockAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy.lock",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Cocoapods,
						FilePath: "testdata/happy.lock",
						Libraries: types.Packages{
							{
								ID:      "AppCenter@4.2.0",
								Name:    "AppCenter",
								Version: "4.2.0",
								DependsOn: []string{
									"AppCenter/Analytics@4.2.0",
									"AppCenter/Crashes@4.2.0",
								},
							},
							{
								ID:      "AppCenter/Analytics@4.2.0",
								Name:    "AppCenter/Analytics",
								Version: "4.2.0",
								DependsOn: []string{
									"AppCenter/Core@4.2.0",
								},
							},
							{
								ID:      "AppCenter/Core@4.2.0",
								Name:    "AppCenter/Core",
								Version: "4.2.0",
							},
							{
								ID:      "AppCenter/Crashes@4.2.0",
								Name:    "AppCenter/Crashes",
								Version: "4.2.0",
								DependsOn: []string{
									"AppCenter/Core@4.2.0",
								},
							},
							{
								ID:      "KeychainAccess@4.2.1",
								Name:    "KeychainAccess",
								Version: "4.2.1",
							},
						},
					},
				},
			},
		},
		{
			name:      "empty file",
			inputFile: "testdata/empty.lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := cocoaPodsLockAnalyzer{}
			got, err := a.Analyze(nil, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			if got != nil {
				for _, app := range got.Applications {
					sort.Sort(app.Libraries)
				}
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
