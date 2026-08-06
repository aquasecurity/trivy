package pkg

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_nodePkgLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name            string
		inputFile       string
		includeChecksum bool
		want            *analyzer.AnalysisResult
		wantErr         string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/package.json",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NodePkg,
						FilePath: "testdata/package.json",
						Packages: types.Packages{
							{
								ID:       "lodash@5.0.0",
								Name:     "lodash",
								Version:  "5.0.0",
								Licenses: []string{"MIT"},
								FilePath: "testdata/package.json",
							},
						},
					},
				},
			},
		},
		{
			name:      "Node.js version header",
			inputFile: "testdata/node_version.h",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NodePkg,
						FilePath: "testdata/node_version.h",
						Packages: types.Packages{
							{
								ID:       "node@26.5.0",
								Name:     "node",
								Version:  "26.5.0",
								FilePath: "testdata/node_version.h",
							},
						},
					},
				},
			},
		},
		{
			name:            "happy path with checksum",
			inputFile:       "testdata/package.json",
			includeChecksum: true,
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NodePkg,
						FilePath: "testdata/package.json",
						Packages: types.Packages{
							{
								ID:       "lodash@5.0.0",
								Name:     "lodash",
								Version:  "5.0.0",
								Licenses: []string{"MIT"},
								FilePath: "testdata/package.json",
								Digest:   "sha1:901a7b55410321c4d35543506cff2a8613ef5aa2",
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path without name",
			inputFile: "testdata/noname.json",
		},
		{
			name:      "sad path",
			inputFile: "testdata/sad.json",
			wantErr:   "JSON decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := nodePkgLibraryAnalyzer{}
			ctx := t.Context()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
				Options:  analyzer.AnalysisOptions{FileChecksum: tt.includeChecksum},
			})

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
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
			name:     "happy path",
			filePath: "nodejs/package.json",
			want:     true,
		},
		{
			name:     "Node.js version header",
			filePath: "usr/local/include/node/node_version.h",
			want:     true,
		},
		{
			name:     "ignore source header",
			filePath: "src/node_version.h",
			want:     false,
		},
		{
			name:     "sad path",
			filePath: "nodejs/package-lock.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := nodePkgLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsPackageRoot(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// Real package roots
		{
			name: "unscoped package root",
			path: "node_modules/rxjs/package.json",
			want: true,
		},
		{
			name: "scoped package root",
			path: "node_modules/@angular/core/package.json",
			want: true,
		},
		{
			name: "nested dep — anchor on inner node_modules",
			path: "node_modules/rxjs/node_modules/foo/package.json",
			want: true,
		},
		{
			name: "pnpm virtual store",
			path: "node_modules/.pnpm/rxjs@6.6.7/node_modules/rxjs/package.json",
			want: true,
		},
		{
			name: "pnpm virtual store, scoped",
			path: "node_modules/.pnpm/@angular+core@13.0.0/node_modules/@angular/core/package.json",
			want: true,
		},
		{
			name: "yarn unplugged",
			path: ".yarn/unplugged/zeromq-virtual-abc/node_modules/zeromq/package.json",
			want: true,
		},

		// Subpath-helper files (the rxjs/ajax case from issue #10607)
		{
			name: "subpath helper unscoped",
			path: "node_modules/rxjs/ajax/package.json",
			want: false,
		},
		{
			name: "subpath helper unscoped — fetch",
			path: "node_modules/rxjs/fetch/package.json",
			want: false,
		},
		{
			name: "subpath helper unscoped — operators",
			path: "node_modules/rxjs/operators/package.json",
			want: false,
		},
		{
			name: "subpath helper scoped",
			path: "node_modules/@angular/core/testing/package.json",
			want: false,
		},
		{
			name: "subpath helper inside pnpm virtual store",
			path: "node_modules/.pnpm/rxjs@6.6.7/node_modules/rxjs/ajax/package.json",
			want: false,
		},
		{
			name: "deep subpath",
			path: "node_modules/foo/a/b/c/package.json",
			want: false,
		},

		// Non-package.json files — never accepted
		{
			name: "non-package.json file",
			path: "node_modules/rxjs/index.js",
			want: false,
		},

		// Outside node_modules — pass through (project root / workspace root)
		{
			name: "project root package.json",
			path: "package.json",
			want: true,
		},
		{
			name: "yarn workspace root",
			path: "packages/foo/package.json",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsPackageRoot(tt.path))
		})
	}
}
