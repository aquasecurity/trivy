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
		// docker run --name uv --rm -it python@sha256:e1141f10176d74d1a0e87a7c0a0a5a98dd98ec5ac12ce867768f40c6feae2fd9 sh
		// wget -qO- https://github.com/astral-sh/uv/releases/download/0.5.8/uv-installer.sh | sh
		// source $HOME/.local/bin/env
		// uv init happy && cd happy
		// uv add pluggy==1.5.0 requests==2.32.3
		// uv add --group test pytest==8.3.4
		{
			dir: "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Uv,
						FilePath: "uv.lock",
						Packages: types.Packages{
							{
								ID:           "happy@0.1.0",
								Name:         "happy",
								Version:      "0.1.0",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"pluggy@1.5.0",
									"pytest@8.3.4",
									"requests@2.32.3",
								},
							},
							{
								ID:           "pluggy@1.5.0",
								Name:         "pluggy",
								Version:      "1.5.0",
								Relationship: types.RelationshipDirect,
							},
							{
								ID:           "pytest@8.3.4",
								Name:         "pytest",
								Version:      "8.3.4",
								Relationship: types.RelationshipDirect,
								Dev:          true,
								DependsOn: []string{
									"colorama@0.4.6",
									"exceptiongroup@1.2.2",
									"iniconfig@2.0.0",
									"packaging@24.2",
									"pluggy@1.5.0",
									"tomli@2.2.1",
								},
							},
							{
								ID:           "requests@2.32.3",
								Name:         "requests",
								Version:      "2.32.3",
								Relationship: types.RelationshipDirect,
								DependsOn: []string{
									"certifi@2024.12.14",
									"charset-normalizer@3.4.0",
									"idna@3.10",
									"urllib3@2.2.3",
								},
							},
							{
								ID:           "certifi@2024.12.14",
								Name:         "certifi",
								Version:      "2024.12.14",
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
								ID:           "colorama@0.4.6",
								Name:         "colorama",
								Version:      "0.4.6",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Dev:          true,
							},
							{
								ID:           "exceptiongroup@1.2.2",
								Name:         "exceptiongroup",
								Version:      "1.2.2",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Dev:          true,
							},
							{
								ID:           "idna@3.10",
								Name:         "idna",
								Version:      "3.10",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
							},
							{
								ID:           "iniconfig@2.0.0",
								Name:         "iniconfig",
								Version:      "2.0.0",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Dev:          true,
							},
							{
								ID:           "packaging@24.2",
								Name:         "packaging",
								Version:      "24.2",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Dev:          true,
							},
							{
								ID:           "tomli@2.2.1",
								Name:         "tomli",
								Version:      "2.2.1",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Dev:          true,
							},
							{
								ID:           "urllib3@2.2.3",
								Name:         "urllib3",
								Version:      "2.2.3",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
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
