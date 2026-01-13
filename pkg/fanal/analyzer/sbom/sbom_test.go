package sbom

import (
	"os"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
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
				Applications: []ftypes.Application{
					{
						Type:     ftypes.Bitnami,
						FilePath: "opt/bitnami/elasticsearch",
						Packages: ftypes.Packages{
							{
								ID:       "elasticsearch@8.9.1",
								Name:     "elasticsearch",
								Version:  "8.9.1",
								Arch:     "arm64",
								Licenses: []string{"Elastic-2.0"},
								Identifier: ftypes.PkgIdentifier{
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
						Type:     ftypes.Jar,
						FilePath: "opt/bitnami/elasticsearch/.spdx-elasticsearch.spdx",
						Packages: ftypes.Packages{
							{
								ID:       "co.elastic.apm:apm-agent:1.36.0",
								Name:     "co.elastic.apm:apm-agent",
								Version:  "1.36.0",
								FilePath: "opt/bitnami/elasticsearch",
								Identifier: ftypes.PkgIdentifier{
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
								Identifier: ftypes.PkgIdentifier{
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
								Identifier: ftypes.PkgIdentifier{
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
								Identifier: ftypes.PkgIdentifier{
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
				Applications: []ftypes.Application{
					{
						Type:     ftypes.Jar,
						FilePath: "opt/bitnami/elasticsearch/.spdx-elasticsearch.cdx",
						Packages: ftypes.Packages{
							{
								FilePath: "opt/bitnami/elasticsearch/modules/apm/elastic-apm-agent-1.36.0.jar",
								ID:       "co.elastic.apm:apm-agent:1.36.0",
								Name:     "co.elastic.apm:apm-agent",
								Version:  "1.36.0",
								Identifier: ftypes.PkgIdentifier{
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
								Identifier: ftypes.PkgIdentifier{
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
				Applications: []ftypes.Application{
					{
						Type:     ftypes.GoBinary,
						FilePath: "layers/sbom/launch/buildpacksio_lifecycle/launcher/sbom.spdx.json",
						Packages: ftypes.Packages{
							{
								ID:      "github.com/buildpacks/lifecycle@v0.20.2",
								Name:    "github.com/buildpacks/lifecycle",
								Version: "v0.20.2",
								Identifier: ftypes.PkgIdentifier{
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
						Type:     ftypes.Jar,
						FilePath: "layers/sbom/launch/buildpacksio_lifecycle/launcher/sbom.spdx.json",
						Packages: ftypes.Packages{
							{
								ID:      "co.elastic.apm:apm-agent:1.36.0",
								Name:    "co.elastic.apm:apm-agent",
								Version: "1.36.0",
								Identifier: ftypes.PkgIdentifier{
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
				Applications: []ftypes.Application{
					{
						Type:     ftypes.Bitnami,
						FilePath: "opt/bitnami/postgresql",
						Packages: ftypes.Packages{
							{
								ID:       "gdal@3.7.1",
								Name:     "gdal",
								Version:  "3.7.1",
								Licenses: []string{"MIT"},
								Identifier: ftypes.PkgIdentifier{
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
								Identifier: ftypes.PkgIdentifier{
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
								Identifier: ftypes.PkgIdentifier{
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
								Identifier: ftypes.PkgIdentifier{
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
				PackageInfos: []ftypes.PackageInfo{
					{
						FilePath: "opt/bitnami/ca-certificates/.spdx-ca-certificates.spdx",
						Packages: ftypes.Packages{
							{
								ID:         "ca-certificates@20230311",
								Name:       "ca-certificates",
								Version:    "20230311",
								Arch:       "all",
								SrcName:    "ca-certificates",
								SrcVersion: "20230311",
								Licenses:   []string{"GPL-2.0-or-later AND GPL-2.0-only AND MPL-2.0"},
								Identifier: ftypes.PkgIdentifier{
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
			got, err := a.Analyze(t.Context(), analyzer.AnalysisInput{
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

func Test_handleActiveStateImages(t *testing.T) {
	tests := []struct {
		name     string
		inputBom *types.SBOM
		want     *types.SBOM
	}{
		{
			name: "skip GoBinary applications",
			inputBom: &types.SBOM{
				Applications: []ftypes.Application{
					{
						Type: ftypes.GoBinary,
						Packages: ftypes.Packages{
							{
								Name:     "github.com/example/module",
								Version:  "v1.0.0",
								FilePath: "/usr/bin/app",
							},
						},
					},
					{
						Type: ftypes.PythonPkg,
						Packages: ftypes.Packages{
							{
								Name:     "requests",
								Version:  "2.28.0",
								FilePath: "/usr/lib/python/site-packages",
							},
						},
					},
				},
			},
			want: &types.SBOM{
				Applications: []ftypes.Application{
					{
						Type:     ftypes.PythonPkg,
						FilePath: "/usr/lib/python/site-packages",
						Packages: ftypes.Packages{
							{
								Name:     "requests",
								Version:  "2.28.0",
								FilePath: "/usr/lib/python/site-packages",
							},
						},
					},
				},
			},
		},
		{
			name: "group packages by filepath and langType",
			inputBom: &types.SBOM{
				Applications: []ftypes.Application{
					{
						Type: ftypes.PythonPkg,
						Packages: ftypes.Packages{
							{
								Name:     "requests",
								Version:  "2.28.0",
								FilePath: "/usr/lib/python/site-packages",
							},
						},
					},
					{
						Type: ftypes.PythonPkg,
						Packages: ftypes.Packages{
							{
								Name:     "flask",
								Version:  "2.0.0",
								FilePath: "/opt/app/venv/lib/python/site-packages",
							},
							{
								Name:     "urllib3",
								Version:  "1.26.0",
								FilePath: "/usr/lib/python/site-packages",
							},
						},
					},
				},
			},
			want: &types.SBOM{
				Applications: []ftypes.Application{
					{
						Type:     ftypes.PythonPkg,
						FilePath: "/usr/lib/python/site-packages",
						Packages: ftypes.Packages{
							{
								Name:     "requests",
								Version:  "2.28.0",
								FilePath: "/usr/lib/python/site-packages",
							},
							{
								Name:     "urllib3",
								Version:  "1.26.0",
								FilePath: "/usr/lib/python/site-packages",
							},
						},
					},
					{
						Type:     ftypes.PythonPkg,
						FilePath: "/opt/app/venv/lib/python/site-packages",
						Packages: ftypes.Packages{
							{
								Name:     "flask",
								Version:  "2.0.0",
								FilePath: "/opt/app/venv/lib/python/site-packages",
							},
						},
					},
				},
			},
		},
		{
			name: "empty filepath packages are grouped",
			inputBom: &types.SBOM{
				Applications: []ftypes.Application{
					{
						Type: ftypes.PythonPkg,
						Packages: ftypes.Packages{
							{
								Name:     "pkg1",
								Version:  "1.0.0",
								FilePath: "",
							},
							{
								Name:     "pkg2",
								Version:  "2.0.0",
								FilePath: "",
							},
						},
					},
				},
			},
			want: &types.SBOM{
				Applications: []ftypes.Application{
					{
						Type:     ftypes.PythonPkg,
						FilePath: "",
						Packages: ftypes.Packages{
							{
								Name:     "pkg1",
								Version:  "1.0.0",
								FilePath: "",
							},
							{
								Name:     "pkg2",
								Version:  "2.0.0",
								FilePath: "",
							},
						},
					},
				},
			},
		},
		{
			name: "all GoBinary applications removed",
			inputBom: &types.SBOM{
				Applications: []ftypes.Application{
					{
						Type: ftypes.GoBinary,
						Packages: ftypes.Packages{
							{
								Name:     "github.com/example/module1",
								Version:  "v1.0.0",
								FilePath: "/usr/bin/app1",
							},
						},
					},
					{
						Type: ftypes.GoBinary,
						Packages: ftypes.Packages{
							{
								Name:     "github.com/example/module2",
								Version:  "v2.0.0",
								FilePath: "/usr/bin/app2",
							},
						},
					},
				},
			},
			want: &types.SBOM{
				Applications: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			HandleActiveStateImages(tt.inputBom)

			// Sort both results for consistent comparison since map iteration order is not guaranteed
			if len(tt.inputBom.Applications) > 0 {
				// Simple sorting by Type and FilePath for comparison
				assert.ElementsMatch(t, tt.want.Applications, tt.inputBom.Applications)
			} else {
				assert.Equal(t, tt.want, tt.inputBom)
			}
		})
	}
}
