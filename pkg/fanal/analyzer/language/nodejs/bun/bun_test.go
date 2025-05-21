package bun

import (
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

func Test_bunLibraryAnalyzer_Analyze(t *testing.T) {
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
						Type:     types.Bun,
						FilePath: "bun.lock",
						Packages: types.Packages{
							{
								ID:           "@types/bun@1.2.13",
								Name:         "@types/bun",
								Version:      "1.2.13",
								Dev:          true,
								Relationship: types.RelationshipDirect,
								DependsOn:    []string{"bun-types@1.2.13"},
								Locations:    types.Locations{types.Location{StartLine: 18, EndLine: 18}},
							},
							{
								ID:           "typescript@5.8.3",
								Name:         "typescript",
								Version:      "5.8.3",
								Relationship: types.RelationshipDirect,
								Locations:    types.Locations{types.Location{StartLine: 24, EndLine: 24}},
							},
							{
								ID:           "zod@3.24.4",
								Name:         "zod",
								Version:      "3.24.4",
								Relationship: types.RelationshipDirect,
								Locations:    types.Locations{types.Location{StartLine: 28, EndLine: 28}},
							},
							{
								ID:           "@types/node@22.15.18",
								Name:         "@types/node",
								Version:      "22.15.18",
								Dev:          true,
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								DependsOn:    []string{"undici-types@6.21.0"},
								Locations:    types.Locations{types.Location{StartLine: 20, EndLine: 20}},
							},
							{
								ID:           "bun-types@1.2.13",
								Name:         "bun-types",
								Version:      "1.2.13",
								Dev:          true,
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								DependsOn:    []string{"@types/node@22.15.18"},
								Locations:    types.Locations{types.Location{StartLine: 22, EndLine: 22}},
							},
							{
								ID:           "undici-types@6.21.0",
								Name:         "undici-types",
								Version:      "6.21.0",
								Dev:          true,
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations:    types.Locations{types.Location{StartLine: 26, EndLine: 26}},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newBunLibraryAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
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

func Test_bunLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "lock file",
			filePath: "bun/bun.lock",
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := bunLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
