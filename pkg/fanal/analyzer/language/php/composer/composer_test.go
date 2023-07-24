package composer

import (
	"context"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func Test_composerAnalyzer_PostAnalyze(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			name: "happy path",
			dir:  "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Composer,
						FilePath: "composer.lock",
						Libraries: types.Packages{
							{
								ID:       "pear/log@1.13.3",
								Name:     "pear/log",
								Version:  "1.13.3",
								Indirect: false,
								Licenses: []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 9,
										EndLine:   68,
									},
								},
								DependsOn: []string{"pear/pear_exception@v1.0.2"},
							},
							{
								ID:       "pear/pear_exception@v1.0.2",
								Name:     "pear/pear_exception",
								Version:  "v1.0.2",
								Indirect: true,
								Licenses: []string{"BSD-2-Clause"},
								Locations: []types.Location{
									{
										StartLine: 69,
										EndLine:   127,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "no composer.json",
			dir:  "testdata/no-composer-json",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Composer,
						FilePath: "composer.lock",
						Libraries: types.Packages{
							{
								ID:       "pear/log@1.13.3",
								Name:     "pear/log",
								Version:  "1.13.3",
								Indirect: false,
								Licenses: []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 9,
										EndLine:   68,
									},
								},
								DependsOn: []string{"pear/pear_exception@v1.0.2"},
							},
							{
								ID:       "pear/pear_exception@v1.0.2",
								Name:     "pear/pear_exception",
								Version:  "v1.0.2",
								Indirect: false,
								Licenses: []string{"BSD-2-Clause"},
								Locations: []types.Location{
									{
										StartLine: 69,
										EndLine:   127,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "wrong composer.json",
			dir:  "testdata/wrong-composer-json",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Composer,
						FilePath: "composer.lock",
						Libraries: types.Packages{
							{
								ID:       "pear/log@1.13.3",
								Name:     "pear/log",
								Version:  "1.13.3",
								Indirect: false,
								Licenses: []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 9,
										EndLine:   68,
									},
								},
								DependsOn: []string{"pear/pear_exception@v1.0.2"},
							},
							{
								ID:       "pear/pear_exception@v1.0.2",
								Name:     "pear/pear_exception",
								Version:  "v1.0.2",
								Indirect: false,
								Licenses: []string{"BSD-2-Clause"},
								Locations: []types.Location{
									{
										StartLine: 69,
										EndLine:   127,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "broken composer.lock",
			dir:  "testdata/sad",
			want: &analyzer.AnalysisResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newComposerAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
