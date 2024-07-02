package executable

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_executableAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     *analyzer.AnalysisResult
	}{
		{
			name:     "binary",
			filePath: "testdata/binary",
			want: &analyzer.AnalysisResult{
				Digests: map[string]string{
					"testdata/binary": "sha256:9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
				},
			},
		},
		{
			name:     "text",
			filePath: "testdata/hello.txt",
			want:     nil,
		},
		{
			name:     "Python binary",
			filePath: "testdata/python2.7",
			want: &analyzer.AnalysisResult{
				Digests: map[string]string{
					"testdata/python2.7": "sha256:c43714431f84c27aa30b4b2368d6570fcafdced12e2e9aa0efb10aeb5cbe5a6b",
				},
				Applications: []types.Application{
					{
						Type:     types.PythonExecutable,
						FilePath: "testdata/python2.7",
						Packages: types.Packages{
							{
								ID:      "python@2.7.18",
								Name:    "python",
								Version: "2.7.18",
							},
						},
					},
				},
			},
		},
		{
			name:     "Php Binary",
			filePath: "testdata/php",
			want: &analyzer.AnalysisResult{
				Digests: map[string]string{
					"testdata/php": "sha256:38afd180eaa357b320cffa30293052b7c732d2e4f8fa8cef9250ef00eef6491c",
				},
				Applications: []types.Application{
					{
						Type:     types.PhpExecutable,
						FilePath: "testdata/php",
						Packages: types.Packages{
							{
								ID:      "php@8.0.7",
								Name:    "php",
								Version: "8.0.7",
							},
						},
					},
				},
			},
		},
		{
			name:     "NodeJS Binary",
			filePath: "testdata/node",
			want: &analyzer.AnalysisResult{
				Digests: map[string]string{
					"testdata/node": "sha256:a96e9711ed4fc86ede60e8992dac02e32edfb41949c8edc36d09318a26ac8c10",
				},
				Applications: []types.Application{
					{
						Type:     types.NodeJsExecutable,
						FilePath: "testdata/node",
						Packages: types.Packages{
							{
								ID:      "node@12.16.3",
								Name:    "node",
								Version: "12.16.3",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.filePath)
			require.NoError(t, err)
			defer f.Close()

			stat, err := f.Stat()
			require.NoError(t, err)

			a := executableAnalyzer{}
			got, err := a.Analyze(context.Background(), analyzer.AnalysisInput{
				FilePath: tt.filePath,
				Content:  f,
				Info:     stat,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
