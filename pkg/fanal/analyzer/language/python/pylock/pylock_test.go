package pylock_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pylock"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_pylockAnalyzer_PostAnalyze(t *testing.T) {
	tests := []struct {
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			dir: "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PyLock,
						FilePath: "pylock.toml",
						Packages: types.Packages{
							{
								ID:      "certifi@2025.1.31",
								Name:    "certifi",
								Version: "2025.1.31",
							},
							{
								ID:      "charset-normalizer@3.4.1",
								Name:    "charset-normalizer",
								Version: "3.4.1",
							},
							{
								ID:      "idna@3.10",
								Name:    "idna",
								Version: "3.10",
							},
							{
								ID:      "requests@2.32.3",
								Name:    "requests",
								Version: "2.32.3",
								DependsOn: []string{
									"certifi@2025.1.31",
									"charset-normalizer@3.4.1",
									"idna@3.10",
									"urllib3@2.3.0",
								},
							},
							{
								ID:      "urllib3@2.3.0",
								Name:    "urllib3",
								Version: "2.3.0",
							},
						},
					},
				},
			},
		},
		{
			dir:  "testdata/broken",
			want: &analyzer.AnalysisResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			a, err := pylock.NewPyLockAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
