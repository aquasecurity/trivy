package mod

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/mapfs"
)

// prepareGOPATH copies testdata/pkg into a temporary directory and
// renames placeholder files: "mod" -> "go.mod" and "sum" -> "go.sum".
// It returns the temporary directory path to be used as GOPATH.
func prepareGOPATH(t *testing.T) string {
	t.Helper()

	gopath := t.TempDir()
	src := filepath.Join("testdata", "pkg")
	dst := filepath.Join(gopath, "pkg")

	// Copy the directory tree
	testutil.CopyDir(t, src, dst)

	// Rename placeholder files inside the copied tree
	err := filepath.WalkDir(dst, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		return renameGoFiles(path)
	})
	require.NoError(t, err)

	return gopath
}

// renameGoFiles switches placeholder names to real Go module filenames.
// "mod" -> "go.mod" and "sum" -> "go.sum".
func renameGoFiles(path string) error {
	name, isDir, ok := placeholderTarget(filepath.Base(path))
	if !ok || isDir {
		return nil
	}
	return os.Rename(path, filepath.Join(filepath.Dir(path), name))
}

// placeholderTarget maps placeholder base names to real targets.
// Returns: targetName, isDir, ok
func placeholderTarget(base string) (string, bool, bool) {
	switch base {
	case "mod":
		return "go.mod", false, true
	case "sum":
		return "go.sum", false, true
	case "vendor":
		return ".", true, true
	default:
		return "", false, false
	}
}

// addTestInput writes/copies test inputs into the in-memory FS
// according to placeholder naming rules.
func addTestInput(t *testing.T, mfs *mapfs.FS, path string) {
	t.Helper()
	target, isDir, ok := placeholderTarget(filepath.Base(path))
	if !ok {
		return
	}

	// vendor dir
	if isDir {
		require.NoError(t, mfs.CopyDir(path, target))
		return
	}

	// go.mod and go.sum files
	require.NoError(t, mfs.WriteFile(target, path))
}

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
			name: "wrong go.mod from `pkg`",
			files: []string{
				"testdata/wrong-gomod-in-pkg/mod",
			},
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
			name: "no pkg dir found",
			files: []string{
				"testdata/no-pkg-found/mod",
			},
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
			name: "no go.sum",
			files: []string{
				"testdata/merge/mod",
			},
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
			name: "sad go.mod",
			files: []string{
				"testdata/sad/mod",
			},
			want: &analyzer.AnalysisResult{},
		},
		{
			name: "deps from GOPATH and license from vendor dir",
			files: []string{
				"testdata/vendor-dir-exists/mod",
				"testdata/vendor-dir-exists/vendor",
			},
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
	for _, tt := range tests {
		// Prepare a temporary GOPATH with restored file names.
		t.Setenv("GOPATH", prepareGOPATH(t))
		t.Run(tt.name, func(t *testing.T) {
			a, err := newGoModAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			mfs := mapfs.New()
			for _, file := range tt.files {
				// Since broken go.mod files bothers IDE, we use placeholders and map them here.
				addTestInput(t, mfs, file)
			}

			ctx := t.Context()
			got, err := a.PostAnalyze(ctx, analyzer.PostAnalysisInput{
				FS: mfs,
			})
			require.NoError(t, err)

			if len(got.Applications) > 0 {
				sort.Sort(got.Applications[0].Packages)
				sort.Sort(tt.want.Applications[0].Packages)
			}
			require.NoError(t, err)
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
