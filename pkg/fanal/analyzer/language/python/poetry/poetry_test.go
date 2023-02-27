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
								ID:       "click@8.1.3",
								Name:     "click",
								Version:  "8.1.3",
								Indirect: true,
								DependsOn: []string{
									"colorama@0.4.6",
								},
							},
							{
								ID:       "colorama@0.4.6",
								Name:     "colorama",
								Version:  "0.4.6",
								Indirect: true,
							},
							{
								ID:      "flask@1.0.3",
								Name:    "flask",
								Version: "1.0.3",
								DependsOn: []string{
									"click@8.1.3",
									"itsdangerous@2.1.2",
									"jinja2@3.1.2",
									"werkzeug@2.2.3",
								},
							},
							{
								ID:       "itsdangerous@2.1.2",
								Name:     "itsdangerous",
								Version:  "2.1.2",
								Indirect: true,
							},
							{
								ID:       "jinja2@3.1.2",
								Name:     "jinja2",
								Version:  "3.1.2",
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
								ID:       "werkzeug@2.2.3",
								Name:     "werkzeug",
								Version:  "2.2.3",
								Indirect: true,
								DependsOn: []string{
									"markupsafe@2.1.2",
								},
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
			name:    "broken poetry.lock",
			dir:     "testdata/sad",
			wantErr: "unable to parse poetry.lock",
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
