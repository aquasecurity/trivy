package sbom

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_sbomAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		filePath string
		want     *analyzer.AnalysisResult
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name:     "valid elasticsearch spdx file",
			file:     "testdata/elasticsearch.spdx.json",
			filePath: "opt/bitnami/elasticsearch/.spdx-elasticsearch.spdx",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type: types.Jar,
						Libraries: types.Packages{
							{
								Name:     "co.elastic.apm:apm-agent",
								Version:  "1.36.0",
								Ref:      "pkg:maven/co.elastic.apm/apm-agent@1.36.0",
								FilePath: "opt/bitnami/elasticsearch",
							},
							{
								Name:     "co.elastic.apm:apm-agent-cached-lookup-key",
								Version:  "1.36.0",
								Ref:      "pkg:maven/co.elastic.apm/apm-agent-cached-lookup-key@1.36.0",
								FilePath: "opt/bitnami/elasticsearch",
							},
							{
								Name:     "co.elastic.apm:apm-agent-common",
								Version:  "1.36.0",
								Ref:      "pkg:maven/co.elastic.apm/apm-agent-common@1.36.0",
								FilePath: "opt/bitnami/elasticsearch",
							},
							{
								Name:     "co.elastic.apm:apm-agent-core",
								Version:  "1.36.0",
								Ref:      "pkg:maven/co.elastic.apm/apm-agent-core@1.36.0",
								FilePath: "opt/bitnami/elasticsearch",
							},
						},
					},
					{
						Type:     types.Bitnami,
						FilePath: "opt/bitnami/elasticsearch",
						Libraries: types.Packages{
							{
								Name:     "elasticsearch",
								Version:  "8.9.1",
								Ref:      "pkg:bitnami/elasticsearch@8.9.1?arch=arm64",
								Arch:     "arm64",
								Licenses: []string{"Elastic-2.0"},
							},
						},
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name:     "valid elasticsearch cdx file",
			file:     "testdata/cdx.json",
			filePath: "opt/bitnami/elasticsearch/.spdx-elasticsearch.cdx",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type: types.Jar,
						Libraries: types.Packages{
							{
								FilePath: "opt/bitnami/elasticsearch/modules/apm/elastic-apm-agent-1.36.0.jar",
								Name:     "co.elastic.apm:apm-agent",
								Version:  "1.36.0",
								Ref:      "pkg:maven/co.elastic.apm/apm-agent@1.36.0",
							},
							{
								FilePath: "opt/bitnami/elasticsearch/modules/apm/elastic-apm-agent-1.36.0.jar",
								Name:     "co.elastic.apm:apm-agent-cached-lookup-key",
								Version:  "1.36.0",
								Ref:      "pkg:maven/co.elastic.apm/apm-agent-cached-lookup-key@1.36.0",
							},
						},
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name:     "valid postgresql spdx file",
			file:     "testdata/postgresql.spdx.json",
			filePath: "opt/bitnami/postgresql/.spdx-postgresql.spdx",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Bitnami,
						FilePath: "opt/bitnami/postgresql",
						Libraries: types.Packages{
							{
								Name:     "gdal",
								Version:  "3.7.1",
								Ref:      "pkg:bitnami/gdal@3.7.1",
								Licenses: []string{"MIT"},
							},
							{
								Name:     "geos",
								Version:  "3.8.3",
								Ref:      "pkg:bitnami/geos@3.8.3",
								Licenses: []string{"LGPL-2.1-only"},
							},
							{
								Name:     "postgresql",
								Version:  "15.3.0",
								Ref:      "pkg:bitnami/postgresql@15.3.0",
								Licenses: []string{"PostgreSQL"},
							},
							{
								Name:     "proj",
								Version:  "6.3.2",
								Ref:      "pkg:bitnami/proj@6.3.2",
								Licenses: []string{"MIT"},
							},
						},
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name:     "invalid spdx file",
			file:     "testdata/invalid_spdx.json",
			filePath: "opt/bitnami/elasticsearch/.spdx-elasticsearch.spdx",
			want:     nil,
			wantErr:  require.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()

			a := sbomAnalyzer{}
			got, err := a.Analyze(context.Background(), analyzer.AnalysisInput{
				FilePath: tt.filePath,
				Content:  f,
			})
			tt.wantErr(t, err)

			if got != nil {
				got.Sort()
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_packagingAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "cdx",
			filePath: "/test/result.cdx",
			want:     true,
		},
		{
			name:     "spdx",
			filePath: "/test/result.spdx",
			want:     true,
		},
		{
			name:     "cdx.json",
			filePath: "/test/result.cdx.json",
			want:     true,
		},
		{
			name:     "spdx.json",
			filePath: "/test/result.spdx.json",
			want:     true,
		},
		{
			name:     "json",
			filePath: "/test/result.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := sbomAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
