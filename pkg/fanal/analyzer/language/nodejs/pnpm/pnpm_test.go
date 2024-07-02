package pnpm

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_pnpmPkgLibraryAnalyzer_Analyze(t *testing.T) {
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
						Type:     types.Pnpm,
						FilePath: "pnpm-lock.yaml",
						Packages: types.Packages{
							{
								ID:           "ms@2.1.3",
								Name:         "ms",
								Version:      "2.1.3",
								Licenses:     []string{"MIT"},
								Relationship: types.RelationshipDirect,
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
						Type:     types.Pnpm,
						FilePath: "pnpm-lock.yaml",
						Packages: types.Packages{
							{
								ID:           "@babel/parser@7.24.7",
								Name:         "@babel/parser",
								Version:      "7.24.7",
								Relationship: types.RelationshipDirect,
								DependsOn:    []string{"@babel/types@7.24.7"},
							},
							{
								ID:           "ms@2.1.3",
								Name:         "ms",
								Version:      "2.1.3",
								Relationship: types.RelationshipDirect,
							},
							{
								ID:           "@babel/helper-string-parser@7.24.7",
								Name:         "@babel/helper-string-parser",
								Version:      "7.24.7",
								Relationship: types.RelationshipIndirect,
								Indirect:     true,
							},
							{
								ID:           "@babel/helper-validator-identifier@7.24.7",
								Name:         "@babel/helper-validator-identifier",
								Version:      "7.24.7",
								Relationship: types.RelationshipIndirect,
								Indirect:     true,
							},
							{
								ID:           "@babel/types@7.24.7",
								Name:         "@babel/types",
								Version:      "7.24.7",
								Relationship: types.RelationshipIndirect,
								Indirect:     true,
								DependsOn: []string{
									"@babel/helper-string-parser@7.24.7",
									"@babel/helper-validator-identifier@7.24.7",
									"to-fast-properties@2.0.0",
								},
							},
							{
								ID:           "to-fast-properties@2.0.0",
								Name:         "to-fast-properties",
								Version:      "2.0.0",
								Relationship: types.RelationshipIndirect,
								Indirect:     true,
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
			a, err := newPnpmAnalyzer(analyzer.AnalyzerOptions{})
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

func Test_pnpmPkgLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "lock file",
			filePath: "pnpm/pnpm-lock.yaml",
			want:     true,
		},
		{
			name:     "lock file in node_modules",
			filePath: "pnpm/node_modules/html2canvas/pnpm-lock.yaml",
			want:     false,
		},
		{
			name:     "package.json in node_modules",
			filePath: "pnpm/node_modules/ms/package.json",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "pnpm/package.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newPnpmAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
