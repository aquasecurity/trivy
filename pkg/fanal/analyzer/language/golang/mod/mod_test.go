package mod

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/mapfs"
)

func Test_gomodAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  *analyzer.AnalysisResult
	}{
		{
			name: "happy",
			files: []string{
				"testdata/happy/mod",
				"testdata/happy/sum",
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Libraries: types.Packages{
							{
								ID:      "github.com/aquasecurity/go-dep-parser@v0.0.0-20220406074731-71021a481237",
								Name:    "github.com/aquasecurity/go-dep-parser",
								Version: "0.0.0-20220406074731-71021a481237",
								Licenses: []string{
									"MIT",
								},
								DependsOn: []string{
									"golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
								},
							},
							{
								ID:       "golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
								Name:     "golang.org/x/xerrors",
								Version:  "0.0.0-20200804184101-5ec99f83aff1",
								Indirect: true,
							},
						},
					},
				},
			},
		},
		{
			name: "wrong go.mod from `pkg`",
			files: []string{
				"testdata/wrong-gomod-in-pkg/mod",
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Libraries: types.Packages{
							{
								ID:      "github.com/sad/sad@v0.0.1",
								Name:    "github.com/sad/sad",
								Version: "0.0.1",
							},
						},
					},
				},
			},
		},
		{
			name: "less than 1.17",
			files: []string{
				"testdata/merge/mod",
				"testdata/merge/sum",
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Libraries: types.Packages{
							{
								ID:      "github.com/aquasecurity/go-dep-parser@v0.0.0-20230219131432-590b1dfb6edd",
								Name:    "github.com/aquasecurity/go-dep-parser",
								Version: "0.0.0-20230219131432-590b1dfb6edd",
								DependsOn: []string{
									"github.com/BurntSushi/toml@v0.3.1",
								},
							},
							{
								ID:       "github.com/BurntSushi/toml@v0.3.1",
								Name:     "github.com/BurntSushi/toml",
								Version:  "0.3.1",
								Indirect: true,
								Licenses: []string{
									"MIT",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "no go.sum",
			files: []string{
				"testdata/merge/mod",
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Libraries: types.Packages{
							{
								ID:        "github.com/aquasecurity/go-dep-parser@v0.0.0-20230219131432-590b1dfb6edd",
								Name:      "github.com/aquasecurity/go-dep-parser",
								Version:   "0.0.0-20230219131432-590b1dfb6edd",
								DependsOn: []string{},
							},
						},
					},
				},
			},
		},
		{
			name: "sad go.mod",
			files: []string{
				"testdata/sad/mod",
			},
			want: &analyzer.AnalysisResult{},
		},
	}
	for _, tt := range tests {
		t.Setenv("GOPATH", "testdata")
		t.Run(tt.name, func(t *testing.T) {
			a, err := newGoModAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			mfs := mapfs.New()
			for _, file := range tt.files {
				// Since broken go.mod files bothers IDE, we should use other file names than "go.mod" and "go.sum".
				if filepath.Base(file) == "mod" {
					require.NoError(t, mfs.WriteFile("go.mod", file))
				} else if filepath.Base(file) == "sum" {
					require.NoError(t, mfs.WriteFile("go.sum", file))
				}
			}

			ctx := context.Background()
			got, err := a.PostAnalyze(ctx, analyzer.PostAnalysisInput{
				FS: mfs,
			})
			assert.NoError(t, err)

			if len(got.Applications) > 0 {
				sort.Sort(got.Applications[0].Libraries)
				sort.Sort(tt.want.Applications[0].Libraries)
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_gomodAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "go.mod",
			filePath: "test/go.mod",
			want:     true,
		},
		{
			name:     "go.sum",
			filePath: "test/foo/go.sum",
			want:     true,
		},
		{
			name:     "sad",
			filePath: "a/b/c/d/test.sum",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := gomodAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
