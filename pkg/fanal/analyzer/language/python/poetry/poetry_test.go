package poetry

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_poetryLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		want    *analyzer.AnalysisResult
		wantErr string
	}{
		{
			name: "happy path",
			dir:  "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Poetry,
						FilePath: "poetry.lock",
						Libraries: []types.Package{
							{
								ID:       "certifi@2022.12.7",
								Name:     "certifi",
								Version:  "2022.12.7",
								Indirect: true,
							},
							{
								ID:       "charset-normalizer@2.1.1",
								Name:     "charset-normalizer",
								Version:  "2.1.1",
								Indirect: true,
							},
							{
								ID:       "click@7.1.2",
								Name:     "click",
								Version:  "7.1.2",
								Indirect: true,
							},
							{
								ID:      "flask@1.1.4",
								Name:    "flask",
								Version: "1.1.4",
								DependsOn: []string{
									"click@7.1.2",
									"itsdangerous@1.1.0",
									"jinja2@2.11.3",
									"werkzeug@1.0.1",
								},
							},
							{
								ID:       "idna@3.4",
								Name:     "idna",
								Version:  "3.4",
								Indirect: true,
							},
							{
								ID:       "itsdangerous@1.1.0",
								Name:     "itsdangerous",
								Version:  "1.1.0",
								Indirect: true,
							},
							{
								ID:       "jinja2@2.11.3",
								Name:     "jinja2",
								Version:  "2.11.3",
								Indirect: true,
								DependsOn: []string{
									"markupsafe@2.1.2",
								},
							},
							{
								ID:       "markupsafe@2.1.2",
								Name:     "markupsafe",
								Version:  "2.1.2",
								Indirect: true,
							},
							{
								ID:      "requests@2.28.1",
								Name:    "requests",
								Version: "2.28.1",
								DependsOn: []string{
									"certifi@2022.12.7",
									"charset-normalizer@2.1.1",
									"idna@3.4",
									"urllib3@1.26.14",
								},
							},
							{
								ID:       "urllib3@1.26.14",
								Name:     "urllib3",
								Version:  "1.26.14",
								Indirect: true,
							},
							{
								ID:       "werkzeug@1.0.1",
								Name:     "werkzeug",
								Version:  "1.0.1",
								Indirect: true,
							},
						},
					},
				},
			},
		},
		{
			name: "no pyproject.toml",
			dir:  "testdata/no-pyproject",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Poetry,
						FilePath: "poetry.lock",
						Libraries: []types.Package{
							{
								ID:      "click@8.1.3",
								Name:    "click",
								Version: "8.1.3",
								DependsOn: []string{
									"colorama@0.4.6",
								},
							},
							{
								ID:      "colorama@0.4.6",
								Name:    "colorama",
								Version: "0.4.6",
							},
						},
					},
				},
			},
		},
		{
			name: "wrong pyproject.toml",
			dir:  "testdata/wrong-pyproject",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Poetry,
						FilePath: "poetry.lock",
						Libraries: []types.Package{
							{
								ID:      "click@8.1.3",
								Name:    "click",
								Version: "8.1.3",
								DependsOn: []string{
									"colorama@0.4.6",
								},
							},
							{
								ID:      "colorama@0.4.6",
								Name:    "colorama",
								Version: "0.4.6",
							},
						},
					},
				},
			},
		},
		{
			name:    "broken poetry.lock",
			dir:     "testdata/sad",
			wantErr: "failed to parse poetry.lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newPoetryAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
