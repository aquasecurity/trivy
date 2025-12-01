package mod

import (
	"sort"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

const gopathFixture = "testdata/gopath.txtar"

func Test_gomodAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name   string
		txtar  string
		gopath bool
		want   *analyzer.AnalysisResult
	}{
		{
			name:   "happy",
			txtar:  "testdata/happy.txtar",
			gopath: true,
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Packages: types.Packages{
							{
								ID:           "github.com/org/repo",
								Name:         "github.com/org/repo",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"github.com/aquasecurity/go-dep-parser@v0.0.0-20220406074731-71021a481237",
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/org/repo",
									},
								},
							},
							{
								ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20220406074731-71021a481237",
								Name:         "github.com/aquasecurity/go-dep-parser",
								Version:      "v0.0.0-20220406074731-71021a481237",
								Relationship: types.RelationshipDirect,
								Licenses:     []string{"MIT"},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/aquasecurity/go-dep-parser",
									},
								},
								DependsOn: []string{
									"golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
								},
							},
							{
								ID:           "golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
								Name:         "golang.org/x/xerrors",
								Version:      "v0.0.0-20200804184101-5ec99f83aff1",
								Relationship: types.RelationshipIndirect,
								Indirect:     true,
							},
						},
					},
				},
			},
		},
		{
			name:   "wrong go.mod from `pkg`",
			txtar:  "testdata/wrong-gomod-in-pkg.txtar",
			gopath: true,
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Packages: types.Packages{
							{
								ID:           "github.com/org/repo",
								Name:         "github.com/org/repo",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"github.com/sad/sad@v0.0.1",
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/org/repo",
									},
								},
							},
							{
								ID:           "github.com/sad/sad@v0.0.1",
								Name:         "github.com/sad/sad",
								Version:      "v0.0.1",
								Relationship: types.RelationshipDirect,
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/sad/sad",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:   "no pkg dir found",
			txtar:  "testdata/no-pkg-found.txtar",
			gopath: false,
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Packages: types.Packages{
							{
								ID:           "github.com/org/repo",
								Name:         "github.com/org/repo",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"github.com/aquasecurity/go-dep-parser@v1.0.0",
									"github.com/aquasecurity/go-version@v1.0.1",
									"golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1", // No parent found, so it's added here.
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/org/repo",
									},
								},
							},
							{
								ID:           "github.com/aquasecurity/go-dep-parser@v1.0.0",
								Name:         "github.com/aquasecurity/go-dep-parser",
								Version:      "v1.0.0",
								Relationship: types.RelationshipDirect,
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/aquasecurity/go-dep-parser",
									},
								},
							},
							{
								ID:           "github.com/aquasecurity/go-version@v1.0.1",
								Name:         "github.com/aquasecurity/go-version",
								Version:      "v1.0.1",
								Relationship: types.RelationshipDirect,
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/aquasecurity/go-version",
									},
								},
							},
							{
								ID:           "golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
								Name:         "golang.org/x/xerrors",
								Version:      "v0.0.0-20200804184101-5ec99f83aff1",
								Relationship: types.RelationshipIndirect,
								Indirect:     true,
							},
						},
					},
				},
			},
		},
		{
			name:   "less than 1.17",
			txtar:  "testdata/merge.txtar",
			gopath: true,
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Packages: types.Packages{
							{
								ID:           "github.com/org/repo",
								Name:         "github.com/org/repo",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"github.com/aquasecurity/go-dep-parser@v0.0.0-20230219131432-590b1dfb6edd",
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/org/repo",
									},
								},
							},
							{
								ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20230219131432-590b1dfb6edd",
								Name:         "github.com/aquasecurity/go-dep-parser",
								Version:      "v0.0.0-20230219131432-590b1dfb6edd",
								Relationship: types.RelationshipDirect,
								DependsOn: []string{
									"github.com/BurntSushi/toml@v0.3.1",
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/aquasecurity/go-dep-parser",
									},
								},
							},
							{
								ID:           "github.com/BurntSushi/toml@v0.3.1",
								Name:         "github.com/BurntSushi/toml",
								Version:      "v0.3.1",
								Relationship: types.RelationshipIndirect,
								Indirect:     true,
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
			name:   "no go.sum",
			txtar:  "testdata/no-go-sum.txtar",
			gopath: true,
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Packages: types.Packages{
							{
								ID:           "github.com/org/repo",
								Name:         "github.com/org/repo",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"github.com/aquasecurity/go-dep-parser@v0.0.0-20230219131432-590b1dfb6edd",
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/org/repo",
									},
								},
							},
							{
								ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20230219131432-590b1dfb6edd",
								Name:         "github.com/aquasecurity/go-dep-parser",
								Version:      "v0.0.0-20230219131432-590b1dfb6edd",
								Relationship: types.RelationshipDirect,
								DependsOn:    []string{},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/aquasecurity/go-dep-parser",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:   "sad go.mod",
			txtar:  "testdata/sad.txtar",
			gopath: false,
			want:   &analyzer.AnalysisResult{},
		},
		{
			name:   "deps from GOPATH and license from vendor dir",
			txtar:  "testdata/vendor-dir-exists.txtar",
			gopath: true,
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Packages: types.Packages{
							{
								ID:           "github.com/org/repo",
								Name:         "github.com/org/repo",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"github.com/aquasecurity/go-dep-parser@v0.0.1",
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/org/repo",
									},
								},
							},
							{
								ID:           "github.com/aquasecurity/go-dep-parser@v0.0.1",
								Name:         "github.com/aquasecurity/go-dep-parser",
								Version:      "v0.0.1",
								Relationship: types.RelationshipDirect,
								Licenses:     []string{"Apache-2.0"},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/aquasecurity/go-dep-parser",
									},
								},
								DependsOn: []string{
									"golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
								},
							},
							{
								ID:           "golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
								Name:         "golang.org/x/xerrors",
								Version:      "v0.0.0-20200804184101-5ec99f83aff1",
								Relationship: types.RelationshipIndirect,
								Indirect:     true,
							},
						},
					},
				},
			},
		},
	}

	// Load GOPATH fixture once as fs.FS (represents $GOPATH/pkg/mod)
	gopathFS := testutil.TxtarToFS(t, gopathFixture)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load test case txtar as fs.FS
			fsys := testutil.TxtarToFS(t, tt.txtar)

			a, err := newGoModAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			// Set GOPATH fs.FS for testing
			ma := a.(*gomodAnalyzer)
			// Use empty fs.FS to simulate no GOPATH scenario
			ma.gopathFS = fstest.MapFS{}
			if tt.gopath {
				ma.gopathFS = gopathFS
			}

			ctx := t.Context()
			got, err := ma.PostAnalyze(ctx, analyzer.PostAnalysisInput{
				FS: fsys,
			})
			require.NoError(t, err)

			if len(got.Applications) > 0 {
				sort.Sort(got.Applications[0].Packages)
				sort.Sort(tt.want.Applications[0].Packages)
			}
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
