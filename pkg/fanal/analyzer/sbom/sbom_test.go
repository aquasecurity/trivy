package sbom

import (
	"context"
	"os"
	"testing"

	"github.com/package-url/packageurl-go"
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
						Type:     types.Bitnami,
						FilePath: "opt/bitnami/elasticsearch",
						Packages: types.Packages{
							{
								ID:       "elasticsearch@8.9.1",
								Name:     "elasticsearch",
								Version:  "8.9.1",
								Arch:     "arm64",
								Licenses: []string{"Elastic-2.0"},
								Identifier: types.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeBitnami,
										Name:    "elasticsearch",
										Version: "8.9.1",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "arch",
												Value: "arm64",
											},
										},
									},
								},
							},
						},
					},
					{
						Type:     types.Jar,
						FilePath: "opt/bitnami/elasticsearch/.spdx-elasticsearch.spdx",
						Packages: types.Packages{
							{
								ID:       "co.elastic.apm:apm-agent:1.36.0",
								Name:     "co.elastic.apm:apm-agent",
								Version:  "1.36.0",
								FilePath: "opt/bitnami/elasticsearch",
								Identifier: types.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "co.elastic.apm",
										Name:      "apm-agent",
										Version:   "1.36.0",
									},
								},
							},
							{
								ID:       "co.elastic.apm:apm-agent-cached-lookup-key:1.36.0",
								Name:     "co.elastic.apm:apm-agent-cached-lookup-key",
								Version:  "1.36.0",
								FilePath: "opt/bitnami/elasticsearch",
								Identifier: types.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "co.elastic.apm",
										Name:      "apm-agent-cached-lookup-key",
										Version:   "1.36.0",
									},
								},
							},
							{
								ID:       "co.elastic.apm:apm-agent-common:1.36.0",
								Name:     "co.elastic.apm:apm-agent-common",
								Version:  "1.36.0",
								FilePath: "opt/bitnami/elasticsearch",
								Identifier: types.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "co.elastic.apm",
										Name:      "apm-agent-common",
										Version:   "1.36.0",
									},
								},
							},
							{
								ID:       "co.elastic.apm:apm-agent-core:1.36.0",
								Name:     "co.elastic.apm:apm-agent-core",
								Version:  "1.36.0",
								FilePath: "opt/bitnami/elasticsearch",
								Identifier: types.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "co.elastic.apm",
										Name:      "apm-agent-core",
										Version:   "1.36.0",
									},
								},
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
						Type:     types.Jar,
						FilePath: "opt/bitnami/elasticsearch/.spdx-elasticsearch.cdx",
						Packages: types.Packages{
							{
								FilePath: "opt/bitnami/elasticsearch/modules/apm/elastic-apm-agent-1.36.0.jar",
								ID:       "co.elastic.apm:apm-agent:1.36.0",
								Name:     "co.elastic.apm:apm-agent",
								Version:  "1.36.0",
								Identifier: types.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "co.elastic.apm",
										Name:      "apm-agent",
										Version:   "1.36.0",
									},
									BOMRef: "pkg:maven/co.elastic.apm/apm-agent@1.36.0",
								},
							},
							{
								FilePath: "opt/bitnami/elasticsearch/modules/apm/elastic-apm-agent-1.36.0.jar",
								ID:       "co.elastic.apm:apm-agent-cached-lookup-key:1.36.0",
								Name:     "co.elastic.apm:apm-agent-cached-lookup-key",
								Version:  "1.36.0",
								Identifier: types.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "co.elastic.apm",
										Name:      "apm-agent-cached-lookup-key",
										Version:   "1.36.0",
									},
									BOMRef: "pkg:maven/co.elastic.apm/apm-agent-cached-lookup-key@1.36.0",
								},
							},
						},
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name:     "valid sbom spdx file without application component",
			file:     "testdata/sbom-without-app-component.spdx.json",
			filePath: "layers/sbom/launch/buildpacksio_lifecycle/launcher/sbom.spdx.json",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoBinary,
						FilePath: "layers/sbom/launch/buildpacksio_lifecycle/launcher/sbom.spdx.json",
						Packages: types.Packages{
							{
								ID:      "github.com/buildpacks/lifecycle@v0.20.2",
								Name:    "github.com/buildpacks/lifecycle",
								Version: "v0.20.2",
								Identifier: types.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeGolang,
										Namespace: "github.com/buildpacks",
										Name:      "lifecycle",
										Version:   "v0.20.2",
									},
								},
								Licenses: []string{
									"NOASSERTION",
								},
							},
						},
					},
					{
						Type:     types.Jar,
						FilePath: "layers/sbom/launch/buildpacksio_lifecycle/launcher/sbom.spdx.json",
						Packages: types.Packages{
							{
								ID:      "co.elastic.apm:apm-agent:1.36.0",
								Name:    "co.elastic.apm:apm-agent",
								Version: "1.36.0",
								Identifier: types.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeMaven,
										Namespace: "co.elastic.apm",
										Name:      "apm-agent",
										Version:   "1.36.0",
									},
								},
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
						Packages: types.Packages{
							{
								ID:       "gdal@3.7.1",
								Name:     "gdal",
								Version:  "3.7.1",
								Licenses: []string{"MIT"},
								Identifier: types.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeBitnami,
										Name:    "gdal",
										Version: "3.7.1",
									},
								},
							},
							{
								ID:       "geos@3.8.3",
								Name:     "geos",
								Version:  "3.8.3",
								Licenses: []string{"LGPL-2.1-only"},
								Identifier: types.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeBitnami,
										Name:    "geos",
										Version: "3.8.3",
									},
								},
							},
							{
								ID:       "postgresql@15.3.0",
								Name:     "postgresql",
								Version:  "15.3.0",
								Licenses: []string{"PostgreSQL"},
								Identifier: types.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeBitnami,
										Name:    "postgresql",
										Version: "15.3.0",
									},
								},
								DependsOn: []string{
									"geos@3.8.3",
									"proj@6.3.2",
									"gdal@3.7.1",
								},
							},
							{
								ID:       "proj@6.3.2",
								Name:     "proj",
								Version:  "6.3.2",
								Licenses: []string{"MIT"},
								Identifier: types.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeBitnami,
										Name:    "proj",
										Version: "6.3.2",
									},
								},
							},
						},
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name:     "valid ca-certificates spdx file",
			file:     "testdata/ca-certificates.spdx.json",
			filePath: "opt/bitnami/ca-certificates/.spdx-ca-certificates.spdx",
			want: &analyzer.AnalysisResult{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "opt/bitnami/ca-certificates/.spdx-ca-certificates.spdx",
						Packages: types.Packages{
							{
								ID:         "ca-certificates@20230311",
								Name:       "ca-certificates",
								Version:    "20230311",
								Arch:       "all",
								SrcName:    "ca-certificates",
								SrcVersion: "20230311",
								Licenses:   []string{"GPL-2.0-or-later AND GPL-2.0-only AND MPL-2.0"},
								Identifier: types.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeDebian,
										Namespace: "debian",
										Name:      "ca-certificates",
										Version:   "20230311",
										Qualifiers: packageurl.Qualifiers{
											{Key: "arch", Value: "all"},
											{Key: "distro", Value: "debian-12.9"},
										},
									},
								},
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
