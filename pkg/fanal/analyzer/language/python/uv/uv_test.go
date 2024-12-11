package uv_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/uv"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_uvAnalyzer_PostAnalyze(t *testing.T) {
	tests := []struct {
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			dir: "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Uv,
						FilePath: "uv.lock",
						Packages: types.Packages{
							{
								ID:           "certifi@2024.8.30",
								Name:         "certifi",
								Version:      "2024.8.30",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
							},
							{
								ID:           "charset-normalizer@3.4.0",
								Name:         "charset-normalizer",
								Version:      "3.4.0",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
							},
							{
								ID:           "idna@3.10",
								Name:         "idna",
								Version:      "3.10",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
							},
							{
								ID:           "pluggy@1.5.0",
								Name:         "pluggy",
								Version:      "1.5.0",
								Relationship: types.RelationshipDirect,
							},
							{
								ID:           "requests@2.32.3",
								Name:         "requests",
								Version:      "2.32.3",
								Relationship: types.RelationshipDirect,
								DependsOn: []string{
									"certifi@2024.8.30",
									"charset-normalizer@3.4.0",
									"idna@3.10",
									"urllib3@2.2.3",
								},
							},
							{
								ID:           "urllib3@2.2.3",
								Name:         "urllib3",
								Version:      "2.2.3",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
							},
							{
								ID:           "uv-test@0.1.0",
								Name:         "uv-test",
								Version:      "0.1.0",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"pluggy@1.5.0",
									"requests@2.32.3",
								},
							},
						},
					},
				},
			},
		},
		{
			dir:  "testdata/broken-lock",
			want: &analyzer.AnalysisResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			a, err := uv.NewUvAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
