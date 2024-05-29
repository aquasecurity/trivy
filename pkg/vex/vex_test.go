package vex_test

import (
	"os"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
)

var (
	ociComponent = core.Component{
		Root: true,
		Type: core.TypeContainerImage,
		Name: "debian:12",
		PkgIdentifier: ftypes.PkgIdentifier{
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
	}
	fsComponent = core.Component{
		Root: true,
		Type: core.TypeFilesystem,
		Name: ".",
	}
	springComponent = core.Component{
		Type:    core.TypeLibrary,
		Group:   "org.springframework.boot",
		Name:    "spring-boot",
		Version: "2.6.0",
		PkgIdentifier: ftypes.PkgIdentifier{
			UID: "01",
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeMaven,
				Namespace: "org.springframework.boot",
				Name:      "spring-boot",
				Version:   "2.6.0",
			},
		},
	}
	bashComponent = core.Component{
		Type:    core.TypeLibrary,
		Name:    "bash",
		Version: "5.3",
		PkgIdentifier: ftypes.PkgIdentifier{
			UID: "02",
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeDebian,
				Namespace: "debian",
				Name:      "bash",
				Version:   "5.2.15",
			},
		},
	}
	goModuleComponent = core.Component{
		Type:    core.TypeLibrary,
		Name:    "github.com/aquasecurity/go-module",
		Version: "1.0.0",
		PkgIdentifier: ftypes.PkgIdentifier{
			UID: "03",
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeGolang,
				Namespace: "github.com/aquasecurity",
				Name:      "go-module",
				Version:   "1.0.0",
			},
		},
	}
	goDirectComponent1 = core.Component{
		Type:    core.TypeLibrary,
		Name:    "github.com/aquasecurity/go-direct1",
		Version: "2.0.0",
		PkgIdentifier: ftypes.PkgIdentifier{
			UID: "04",
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeGolang,
				Namespace: "github.com/aquasecurity",
				Name:      "go-direct1",
				Version:   "2.0.0",
			},
		},
	}
	goDirectComponent2 = core.Component{
		Type:    core.TypeLibrary,
		Name:    "github.com/aquasecurity/go-direct2",
		Version: "3.0.0",
		PkgIdentifier: ftypes.PkgIdentifier{
			UID: "05",
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeGolang,
				Namespace: "github.com/aquasecurity",
				Name:      "go-direct2",
				Version:   "3.0.0",
			},
		},
	}
	goTransitiveComponent = core.Component{
		Type:    core.TypeLibrary,
		Name:    "github.com/aquasecurity/go-transitive",
		Version: "4.0.0",
		PkgIdentifier: ftypes.PkgIdentifier{
			UID: "06",
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeGolang,
				Namespace: "github.com/aquasecurity",
				Name:      "go-transitive",
				Version:   "4.0.0",
			},
		},
	}
	argoComponent = core.Component{
		Type:    core.TypeLibrary,
		Name:    "argo-cd",
		Version: "2.9.3-2",
		PkgIdentifier: ftypes.PkgIdentifier{
			UID: "07",
			PURL: &packageurl.PackageURL{
				Type:    packageurl.TypeBitnami,
				Name:    "argo-cd",
				Version: "2.9.3-2",
				Qualifiers: packageurl.Qualifiers{
					{
						Key:   "arch",
						Value: "amd64",
					},
					{
						Key:   "distro",
						Value: "debian-12",
					},
				},
			},
		},
	}
	clientGoComponent = core.Component{
		Type:    core.TypeLibrary,
		Name:    "k8s.io/client-go",
		Version: "0.24.2",
		PkgIdentifier: ftypes.PkgIdentifier{
			UID: "08",
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeGolang,
				Namespace: "k8s.io",
				Name:      "client-go",
				Version:   "0.24.2",
			},
		},
	}
	vuln1 = types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2021-44228",
		PkgName:          springComponent.Name,
		InstalledVersion: springComponent.Version,
		PkgIdentifier: ftypes.PkgIdentifier{
			UID:  springComponent.PkgIdentifier.UID,
			PURL: springComponent.PkgIdentifier.PURL,
		},
	}
	vuln2 = types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2021-0001",
		PkgName:          springComponent.Name,
		InstalledVersion: springComponent.Version,
		PkgIdentifier: ftypes.PkgIdentifier{
			UID:  springComponent.PkgIdentifier.UID,
			PURL: springComponent.PkgIdentifier.PURL,
		},
	}
	vuln3 = types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2022-3715",
		PkgName:          bashComponent.Name,
		InstalledVersion: bashComponent.Version,
		PkgIdentifier: ftypes.PkgIdentifier{
			UID:  bashComponent.PkgIdentifier.UID,
			PURL: bashComponent.PkgIdentifier.PURL,
		},
	}
	vuln4 = types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2024-0001",
		PkgName:          goTransitiveComponent.Name,
		InstalledVersion: goTransitiveComponent.Version,
		PkgIdentifier: ftypes.PkgIdentifier{
			UID:  goTransitiveComponent.PkgIdentifier.UID,
			PURL: goTransitiveComponent.PkgIdentifier.PURL,
		},
	}
	vuln5 = types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2023-2727",
		PkgName:          clientGoComponent.Name,
		InstalledVersion: clientGoComponent.Version,
		PkgIdentifier: ftypes.PkgIdentifier{
			UID:  clientGoComponent.PkgIdentifier.UID,
			PURL: clientGoComponent.PkgIdentifier.PURL,
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
				bom:   newTestBOM1(),
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
				bom: newTestBOM1(),
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
				bom: newTestBOM1(),
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
			name: "OpenVEX, single path between product and subcomponent",
			fields: fields{
				filePath: "testdata/openvex-nested.json",
			},
			args: args{
				vulns: []types.DetectedVulnerability{vuln4},
				bom:   newTestBOM3(),
			},
			want: []types.DetectedVulnerability{},
		},
		{
			name: "OpenVEX, multi paths between product and subcomponent",
			fields: fields{
				filePath: "testdata/openvex-nested.json",
			},
			args: args{
				vulns: []types.DetectedVulnerability{vuln4},
				bom:   newTestBOM4(),
			},
			want: []types.DetectedVulnerability{vuln4}, // Will not be filtered because of multi paths
		},
		{
			name: "CycloneDX SBOM with CycloneDX VEX",
			fields: fields{
				filePath: "testdata/cyclonedx.json",
				report: types.Report{
					ArtifactType: artifact.TypeCycloneDX,
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
					ArtifactType: artifact.TypeCycloneDX,
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
			name: "CSAF, not affected",
			fields: fields{
				filePath: "testdata/csaf.json",
			},
			args: args{
				bom:   newTestBOM5(),
				vulns: []types.DetectedVulnerability{vuln5},
			},
			want: []types.DetectedVulnerability{},
		},
		{
			name: "CSAF with relationships, not affected",
			fields: fields{
				filePath: "testdata/csaf-relationships.json",
			},
			args: args{
				bom:   newTestBOM5(),
				vulns: []types.DetectedVulnerability{vuln5},
			},
			want: []types.DetectedVulnerability{},
		},
		{
			name: "CSAF with relationships, affected",
			fields: fields{
				filePath: "testdata/csaf-relationships.json",
			},
			args: args{
				bom:   newTestBOM6(),
				vulns: []types.DetectedVulnerability{vuln5},
			},
			want: []types.DetectedVulnerability{vuln5},
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

func newTestBOM1() *core.BOM {
	// - oci:debian?tag=12
	//     - pkg:maven/org.springframework.boot/spring-boot@2.6.0
	//     - pkg:deb/debian/bash@5.3
	bom := core.NewBOM(core.Options{Parents: true})
	bom.AddComponent(&ociComponent)
	bom.AddComponent(&springComponent)
	bom.AddComponent(&bashComponent)
	bom.AddRelationship(&ociComponent, &springComponent, core.RelationshipContains)
	bom.AddRelationship(&ociComponent, &bashComponent, core.RelationshipContains)
	return bom
}

func newTestBOM2() *core.BOM {
	bom := core.NewBOM(core.Options{})
	bom.AddComponent(&core.Component{
		Root: true,
		Type: core.TypeContainerImage,
		Name: "ubuntu:24.04",
		PkgIdentifier: ftypes.PkgIdentifier{
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

func newTestBOM3() *core.BOM {
	// - filesystem
	//     - pkg:golang/github.com/aquasecurity/go-module@1.0.0
	//         - pkg:golang/github.com/aquasecurity/go-direct1@2.0.0
	//             - pkg:golang/github.com/aquasecurity/go-transitive@4.0.0
	bom := core.NewBOM(core.Options{Parents: true})
	bom.AddComponent(&fsComponent)
	bom.AddComponent(&goModuleComponent)
	bom.AddComponent(&goDirectComponent1)
	bom.AddComponent(&goTransitiveComponent)
	bom.AddRelationship(&fsComponent, &goModuleComponent, core.RelationshipContains)
	bom.AddRelationship(&goModuleComponent, &goDirectComponent1, core.RelationshipDependsOn)
	bom.AddRelationship(&goDirectComponent1, &goTransitiveComponent, core.RelationshipDependsOn)
	return bom
}

func newTestBOM4() *core.BOM {
	// - filesystem
	//     - pkg:golang/github.com/aquasecurity/go-module@2.0.0
	//         - pkg:golang/github.com/aquasecurity/go-direct1@3.0.0
	//             - pkg:golang/github.com/aquasecurity/go-transitive@5.0.0
	//         - pkg:golang/github.com/aquasecurity/go-direct2@4.0.0
	//             - pkg:golang/github.com/aquasecurity/go-transitive@5.0.0
	bom := core.NewBOM(core.Options{Parents: true})
	bom.AddComponent(&fsComponent)
	bom.AddComponent(&goModuleComponent)
	bom.AddComponent(&goDirectComponent1)
	bom.AddComponent(&goDirectComponent2)
	bom.AddComponent(&goTransitiveComponent)
	bom.AddRelationship(&fsComponent, &goModuleComponent, core.RelationshipContains)
	bom.AddRelationship(&goModuleComponent, &goDirectComponent1, core.RelationshipDependsOn)
	bom.AddRelationship(&goModuleComponent, &goDirectComponent2, core.RelationshipDependsOn)
	bom.AddRelationship(&goDirectComponent1, &goTransitiveComponent, core.RelationshipDependsOn)
	bom.AddRelationship(&goDirectComponent2, &goTransitiveComponent, core.RelationshipDependsOn)
	return bom
}

func newTestBOM5() *core.BOM {
	// - oci:debian?tag=12
	//     - pkg:bitnami/argo-cd@2.9.3-2?arch=amd64&distro=debian-12
	//         - pkg:golang/k8s.io/client-go@0.24.2
	bom := core.NewBOM(core.Options{Parents: true})
	bom.AddComponent(&ociComponent)
	bom.AddComponent(&argoComponent)
	bom.AddComponent(&clientGoComponent)
	bom.AddRelationship(&ociComponent, &argoComponent, core.RelationshipContains)
	bom.AddRelationship(&argoComponent, &clientGoComponent, core.RelationshipDependsOn)
	return bom
}

func newTestBOM6() *core.BOM {
	// - oci:debian?tag=12
	//     - pkg:golang/k8s.io/client-go@0.24.2
	bom := core.NewBOM(core.Options{Parents: true})
	bom.AddComponent(&ociComponent)
	bom.AddComponent(&clientGoComponent)
	bom.AddRelationship(&ociComponent, &clientGoComponent, core.RelationshipContains)
	return bom
}
