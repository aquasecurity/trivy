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
		name      string
		filePath  string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "go.mod",
			filePath:  "testdata/go.mod",
			inputFile: "testdata/normal_go.mod",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "testdata/go.mod",
						Libraries: []types.Package{
							{
								Name:    "github.com/aquasecurity/go-dep-parser",
								Version: "0.0.0-20220406074731-71021a481237",
							},
							{
								Name: "golang.org/x/xerrors", Version: "0.0.0-20200804184101-5ec99f83aff1",
								Indirect: true,
							},
						},
					},
				},
			},
		},
		{
			name:      "go.sum",
			filePath:  "testdata/go.sum",
			inputFile: "testdata/normal_go.sum",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "testdata/go.sum",
						Libraries: []types.Package{
							{Name: "github.com/BurntSushi/toml", Version: "0.3.1"},
							{Name: "github.com/cpuguy83/go-md2man/v2", Version: "2.0.0-20190314233015-f79a8a8ca69d"},
							{Name: "github.com/davecgh/go-spew", Version: "1.1.0"},
							{Name: "github.com/pmezard/go-difflib", Version: "1.0.0"},
							{Name: "github.com/russross/blackfriday/v2", Version: "2.0.1"},
							{Name: "github.com/shurcooL/sanitized_anchor_name", Version: "1.0.0"},
							{Name: "github.com/stretchr/objx", Version: "0.1.0"},
							{Name: "github.com/stretchr/testify", Version: "1.7.0"},
							{Name: "github.com/urfave/cli", Version: "1.22.5"},
							{Name: "golang.org/x/xerrors", Version: "0.0.0-20200804184101-5ec99f83aff1"},
							{Name: "gopkg.in/check.v1", Version: "0.0.0-20161208181325-20d25e280405"},
							{Name: "gopkg.in/yaml.v2", Version: "2.2.2"},
							{Name: "gopkg.in/yaml.v3", Version: "3.0.0-20200313102051-9f266ea9e77c"},
						},
					},
				},
			},
		},
		{
			name:      "sad go.mod",
			filePath:  "testdata/go.mod",
			inputFile: "testdata/sad_go.mod",
			wantErr:   "unknown directive",
		},
		{
			name:      "sad go.sum",
			filePath:  "testdata/go.sum",
			inputFile: "testdata/sad_go.sum",
			want:      nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := gomodAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.filePath,
				Content:  f,
			})

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
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
