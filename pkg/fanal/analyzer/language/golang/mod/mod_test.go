package mod

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_gomodAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		want    *analyzer.AnalysisResult
		wantErr string
	}{
		{
			name: "happy",
			dir:  "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Libraries: []types.Package{
							{
								Name:    "github.com/aquasecurity/go-dep-parser",
								Version: "0.0.0-20220406074731-71021a481237",
							},
							{
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
			name: "less than 1.17",
			dir:  "testdata/merge",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Libraries: []types.Package{
							{
								Name:    "github.com/aquasecurity/go-dep-parser",
								Version: "0.0.0-20230219131432-590b1dfb6edd",
							},
							{
								Name:     "github.com/BurntSushi/toml",
								Version:  "0.3.1",
								Indirect: true,
							},
						},
					},
				},
			},
		},
		{
			name: "no go.sum",
			dir:  "testdata/no_gosum",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Libraries: []types.Package{
							{
								Name:    "github.com/aquasecurity/go-dep-parser",
								Version: "0.0.0-20211110174639-8257534ffed3",
							},
						},
					},
				},
			},
		},
		{
			name:    "sad go.mod",
			dir:     "testdata/sad",
			wantErr: "unknown directive",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newGoModAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			ctx := context.Background()
			got, err := a.PostAnalyze(ctx, analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			if got != nil {
				slices.SortFunc(got.Applications[0].Libraries, func(a, b types.Package) bool {
					return a.Name < b.Name
				})
				slices.SortFunc(tt.want.Applications[0].Libraries, func(a, b types.Package) bool {
					return a.Name < b.Name
				})
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
