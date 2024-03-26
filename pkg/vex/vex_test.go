package vex_test

import (
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"os"
	"testing"

	"github.com/package-url/packageurl-go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
)

var (
	vuln1 = types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2021-44228",
		PkgName:          "spring-boot",
		InstalledVersion: "2.6.0",
		PkgIdentifier: ftypes.PkgIdentifier{
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeMaven,
				Namespace: "org.springframework.boot",
				Name:      "spring-boot",
				Version:   "2.6.0",
			},
		},
	}
	vuln2 = types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2021-0001",
		PkgName:          "spring-boot",
		InstalledVersion: "2.6.0",
		PkgIdentifier: ftypes.PkgIdentifier{
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeMaven,
				Namespace: "org.springframework.boot",
				Name:      "spring-boot",
				Version:   "2.6.0",
			},
		},
	}
	vuln3 = types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2022-3715",
		PkgName:          "bash",
		InstalledVersion: "5.2.15",
		PkgIdentifier: ftypes.PkgIdentifier{
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeDebian,
				Namespace: "debian",
				Name:      "bash",
				Version:   "5.2.15",
			},
		},
	}
)

func TestMain(m *testing.M) {
	log.InitLogger(false, true)
	os.Exit(m.Run())
}

func TestVEX_Filter(t *testing.T) {
	type fields struct {
		filePath string
		report   types.Report
	}
	type args struct {
		vulns []types.DetectedVulnerability
		bom   *core.BOM
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []types.DetectedVulnerability
		wantErr string
	}{
		{
			name: "OpenVEX",
			fields: fields{
				filePath: "testdata/openvex.json",
			},
			args: args{
				vulns: []types.DetectedVulnerability{vuln1},
				bom:   newTestBOM(),
			},
			want: []types.DetectedVulnerability{},
		},
		{
			name: "OpenVEX, multiple statements",
			fields: fields{
				filePath: "testdata/openvex-multiple.json",
			},
			args: args{
				vulns: []types.DetectedVulnerability{
					vuln1, // filtered by VEX
					vuln2,
				},
				bom: newTestBOM(),
			},
			want: []types.DetectedVulnerability{
				vuln2,
			},
		},
		{
			name: "OpenVEX, subcomponents, oci image",
			fields: fields{
				filePath: "testdata/openvex-oci.json",
			},
			args: args{
				vulns: []types.DetectedVulnerability{
					vuln3,
				},
				bom: newTestBOM(),
			},
			want: []types.DetectedVulnerability{},
		},
		{
			name: "OpenVEX, subcomponents, wrong oci image",
			fields: fields{
				filePath: "testdata/openvex-oci.json",
			},
			args: args{
				vulns: []types.DetectedVulnerability{vuln3},
				bom:   newTestBOM2(),
			},
			want: []types.DetectedVulnerability{vuln3},
		},
		{
			name: "CycloneDX SBOM with CycloneDX VEX",
			fields: fields{
				filePath: "testdata/cyclonedx.json",
				report: types.Report{
					ArtifactType: ftypes.ArtifactCycloneDX,
					BOM: &core.BOM{
						SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
						Version:      1,
					},
				},
			},
			args: args{
				vulns: []types.DetectedVulnerability{
					{
						VulnerabilityID:  "CVE-2018-7489",
						PkgName:          "jackson-databind",
						InstalledVersion: "2.8.0",
						PkgIdentifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeMaven,
								Namespace: "com.fasterxml.jackson.core",
								Name:      "jackson-databind",
								Version:   "2.8.0",
							},
						},
					},
					{
						VulnerabilityID:  "CVE-2018-7490",
						PkgName:          "jackson-databind",
						InstalledVersion: "2.8.0",
						PkgIdentifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeMaven,
								Namespace: "com.fasterxml.jackson.core",
								Name:      "jackson-databind",
								Version:   "2.8.0",
							},
						},
					},
					{
						VulnerabilityID:  "CVE-2022-27943",
						PkgID:            "libstdc++6@12.3.0-1ubuntu1~22.04",
						PkgName:          "libstdc++6",
						InstalledVersion: "12.3.0-1ubuntu1~22.04",
						PkgIdentifier: ftypes.PkgIdentifier{
							BOMRef: "pkg:deb/ubuntu/libstdc%2B%2B6@12.3.0-1ubuntu1~22.04?distro=ubuntu-22.04&arch=amd64",
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeDebian,
								Namespace: "ubuntu",
								Name:      "libstdc++6",
								Version:   "12.3.0-1ubuntu1~22.04",
								Qualifiers: []packageurl.Qualifier{
									{
										Key:   "arch",
										Value: "amd64",
									},
									{
										Key:   "distro",
										Value: "ubuntu-22.04",
									},
								},
							},
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2018-7490",
					PkgName:          "jackson-databind",
					InstalledVersion: "2.8.0",
					PkgIdentifier: ftypes.PkgIdentifier{
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeMaven,
							Namespace: "com.fasterxml.jackson.core",
							Name:      "jackson-databind",
							Version:   "2.8.0",
						},
					},
				},
			},
		},
		{
			name: "CycloneDX VEX wrong URN",
			fields: fields{
				filePath: "testdata/cyclonedx.json",
				report: types.Report{
					ArtifactType: ftypes.ArtifactCycloneDX,
					BOM: &core.BOM{
						SerialNumber: "urn:uuid:wrong",
						Version:      1,
					},
				},
			},
			args: args{
				vulns: []types.DetectedVulnerability{
					{
						VulnerabilityID:  "CVE-2018-7489",
						PkgName:          "jackson-databind",
						InstalledVersion: "2.8.0",
						PkgIdentifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeMaven,
								Namespace: "com.fasterxml.jackson.core",
								Name:      "jackson-databind",
								Version:   "2.8.0",
							},
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2018-7489",
					PkgName:          "jackson-databind",
					InstalledVersion: "2.8.0",
					PkgIdentifier: ftypes.PkgIdentifier{
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeMaven,
							Namespace: "com.fasterxml.jackson.core",
							Name:      "jackson-databind",
							Version:   "2.8.0",
						},
					},
				},
			},
		},
		{
			name: "CSAF (not affected vuln)",
			fields: fields{
				filePath: "testdata/csaf-not-affected.json",
			},
			args: args{
				vulns: []types.DetectedVulnerability{
					{
						VulnerabilityID:  "CVE-2021-44228",
						PkgName:          "spring-boot",
						InstalledVersion: "2.6.0",
						PkgIdentifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeMaven,
								Namespace: "org.springframework.boot",
								Name:      "spring-boot",
								Version:   "2.6.0",
							},
						},
					},
				},
			},
			want: []types.DetectedVulnerability{},
		},
		{
			name: "CSAF (affected vuln)",
			fields: fields{
				filePath: "testdata/csaf-affected.json",
			},
			args: args{
				vulns: []types.DetectedVulnerability{
					{
						VulnerabilityID:  "CVE-2021-44228",
						PkgName:          "def",
						InstalledVersion: "1.0",
						PkgIdentifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeMaven,
								Namespace: "org.example.company",
								Name:      "def",
								Version:   "1.0",
							},
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2021-44228",
					PkgName:          "def",
					InstalledVersion: "1.0",
					PkgIdentifier: ftypes.PkgIdentifier{
						PURL: &packageurl.PackageURL{
							Type:      packageurl.TypeMaven,
							Namespace: "org.example.company",
							Name:      "def",
							Version:   "1.0",
						},
					},
				},
			},
		},
		{
			name: "CSAF (not affected vuln) with sub components",
			fields: fields{
				filePath: "testdata/csaf-not-affected-sub-components.json",
			},
			args: args{
				vulns: []types.DetectedVulnerability{
					{
						VulnerabilityID:  "CVE-2023-2727",
						PkgName:          "kubernetes",
						InstalledVersion: "v1.24.2",
						PkgIdentifier: ftypes.PkgIdentifier{
							PURL: &packageurl.PackageURL{
								Type:      packageurl.TypeGolang,
								Namespace: "k8s.io",
								Name:      "kubernetes",
								Version:   "v1.24.2",
							},
						},
					},
				},
			},
			want: []types.DetectedVulnerability{},
		},
		{
			name: "unknown format",
			fields: fields{
				filePath: "testdata/unknown.json",
			},
			args:    args{},
			wantErr: "unable to load VEX",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := vex.New(tt.fields.filePath, tt.fields.report)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			got := &types.Result{
				Vulnerabilities: tt.args.vulns,
			}
			v.Filter(got, tt.args.bom)
			assert.Equal(t, tt.want, got.Vulnerabilities)
		})
	}
}

func newTestBOM() *core.BOM {
	bom := core.NewBOM(core.Options{})
	bom.AddComponent(&core.Component{
		Root: true,
		Type: core.TypeContainerImage,
		Name: "debian:12",
		PkgID: core.PkgID{
			PURL: &packageurl.PackageURL{
				Type:    packageurl.TypeOCI,
				Name:    "debian",
				Version: "sha256:4482958b4461ff7d9fabc24b3a9ab1e9a2c85ece07b2db1840c7cbc01d053e90",
				Qualifiers: packageurl.Qualifiers{
					{
						Key:   "tag",
						Value: "12",
					},
					{
						Key:   "repository_url",
						Value: "docker.io/library/debian",
					},
				},
			},
		},
	})
	return bom
}

func newTestBOM2() *core.BOM {
	bom := core.NewBOM(core.Options{})
	bom.AddComponent(&core.Component{
		Root: true,
		Type: core.TypeContainerImage,
		Name: "ubuntu:24.04",
		PkgID: core.PkgID{
			PURL: &packageurl.PackageURL{
				Type:    packageurl.TypeOCI,
				Name:    "ubuntu",
				Version: "sha256:4482958b4461ff7d9fabc24b3a9ab1e9a2c85ece07b2db1840c7cbc01d053e90",
				Qualifiers: packageurl.Qualifiers{
					{
						Key:   "tag",
						Value: "24.04",
					},
					{
						Key:   "repository_url",
						Value: "docker.io/library/ubuntu",
					},
				},
			},
		},
	})
	return bom
}
