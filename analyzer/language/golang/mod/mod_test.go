package mod

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
)

func Test_gomodAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/gomod_many.sum",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoMod,
						FilePath: "testdata/gomod_many.sum",
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
		}, {
			name:      "sad path",
			inputFile: "testdata/invalid.txt",
			want:      nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := os.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := gomodAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisTarget{
				FilePath: tt.inputFile,
				Content:  b,
			})

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			if got != nil {
				sort.Slice(got.Applications[0].Libraries, func(i, j int) bool {
					return got.Applications[0].Libraries[i].Name < got.Applications[0].Libraries[j].Name
				})
				sort.Slice(tt.want.Applications[0].Libraries, func(i, j int) bool {
					return tt.want.Applications[0].Libraries[i].Name < tt.want.Applications[0].Libraries[j].Name
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
			name:     "happy",
			filePath: "test/go.sum",
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
