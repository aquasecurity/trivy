package npm

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func TestMain(m *testing.M) {
	log.InitLogger(false, true)
	os.Exit(m.Run())
}

func Test_npmLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			name: "with node_modules",
			dir:  "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Npm,
						FilePath: "package-lock.json",
						Packages: types.Packages{
							{
								ID:       "@babel/parser@7.23.6",
								Name:     "@babel/parser",
								Version:  "7.23.6",
								Licenses: []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 6,
										EndLine:   10,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/@babel/parser/-/parser-7.23.6.tgz",
									},
								},
							},
							{
								ID:      "ansi-colors@3.2.3",
								Name:    "ansi-colors",
								Version: "3.2.3",
								Dev:     true,
								Locations: []types.Location{
									{
										StartLine: 11,
										EndLine:   16,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/ansi-colors/-/ansi-colors-3.2.3.tgz",
									},
								},
							},
							{
								ID:      "array-flatten@1.1.1",
								Name:    "array-flatten",
								Version: "1.1.1",
								Locations: []types.Location{
									{
										StartLine: 17,
										EndLine:   21,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/array-flatten/-/array-flatten-1.1.1.tgz",
									},
								},
							},
							{
								ID:        "body-parser@1.18.3",
								Name:      "body-parser",
								Version:   "1.18.3",
								DependsOn: []string{"debug@2.6.9"},
								Licenses:  []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   44,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/body-parser/-/body-parser-1.18.3.tgz",
									},
								},
							},
							{
								ID:        "debug@2.6.9",
								Name:      "debug",
								Version:   "2.6.9",
								DependsOn: []string{"ms@2.0.0"},
								Licenses:  []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 30,
										EndLine:   37,
									},
									{
										StartLine: 53,
										EndLine:   60,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
									},
								},
							},
							{
								ID:        "express@4.16.4",
								Name:      "express",
								Version:   "4.16.4",
								DependsOn: []string{"debug@2.6.9"},
								Licenses:  []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 45,
										EndLine:   67,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/express/-/express-4.16.4.tgz",
									},
								},
							},
							{
								ID:       "ms@2.0.0",
								Name:     "ms",
								Version:  "2.0.0",
								Licenses: []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 38,
										EndLine:   42,
									},
									{
										StartLine: 61,
										EndLine:   65,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz",
									},
								},
							},
							{
								ID:       "ms@2.1.1",
								Name:     "ms",
								Version:  "2.1.1",
								Licenses: []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 68,
										EndLine:   72,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/ms/-/ms-2.1.1.tgz",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "without node_modules",
			dir:  "testdata/no-node_modules",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Npm,
						FilePath: "package-lock.json",
						Packages: types.Packages{
							{
								ID:      "ms@2.1.1",
								Name:    "ms",
								Version: "2.1.1",
								Locations: []types.Location{
									{
										StartLine: 6,
										EndLine:   10,
									},
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefOther,
										URL:  "https://registry.npmjs.org/ms/-/ms-2.1.1.tgz",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "sad path",
			dir:  "testdata/sad",
			want: &analyzer.AnalysisResult{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newNpmLibraryAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			if len(got.Applications) > 0 {
				sort.Sort(got.Applications[0].Packages)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_nodePkgLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "lock file",
			filePath: "npm/package-lock.json",
			want:     true,
		},
		{
			name:     "package.json",
			filePath: "npm/node_modules/ms/package.json",
			want:     true,
		},
		{
			name:     "package.json with `/` in name",
			filePath: "npm/node_modules/@babel/parser/package.json",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "npm/package.json",
			want:     false,
		},
		{
			name:     "lock file in node_modules",
			filePath: "npm/node_modules/html2canvas/package-lock.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := npmLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
