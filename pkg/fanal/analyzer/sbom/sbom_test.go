package sbom

import (
	"context"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func Test_sbomAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		want    *analyzer.AnalysisResult
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "valid spdx file",
			file: "testdata/spdx.json",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Jar,
						FilePath: "opt/bitnami/bin/elasticsearch",
						Libraries: types.Packages{
							{
								FilePath: "opt/bitnami/modules/apm/elastic-apm-agent-1.36.0.jar",
								Name:     "co.elastic.apm:apm-agent",
								Version:  "1.36.0",
								Ref:      "pkg:maven/co.elastic.apm/apm-agent@1.36.0",
							},
							{
								FilePath: "opt/bitnami/modules/apm/elastic-apm-agent-1.36.0.jar",
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
			name: "valid cdx file",
			file: "testdata/cdx.json",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Jar,
						FilePath: "opt/bitnami/bin/elasticsearch",
						Libraries: types.Packages{
							{
								FilePath: "opt/bitnami/modules/apm/elastic-apm-agent-1.36.0.jar",
								Name:     "co.elastic.apm:apm-agent",
								Version:  "1.36.0",
								Ref:      "pkg:maven/co.elastic.apm/apm-agent@1.36.0",
							},
							{
								FilePath: "opt/bitnami/modules/apm/elastic-apm-agent-1.36.0.jar",
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
			name:    "invalid spdx file",
			file:    "testdata/invalid_spdx.json",
			want:    nil,
			wantErr: require.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()

			a := sbomAnalyzer{}
			got, err := a.Analyze(context.Background(), analyzer.AnalysisInput{
				FilePath: "opt/bitnami/.spdx-elasticsearch.spdx",
				Content:  f,
			})
			tt.wantErr(t, err)
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
