package vex_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1"
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

const (
	vulnerableCodeNotInExecutePath = "vulnerable_code_not_in_execute_path"
	codeNotReachable               = "code_not_reachable"
)

var (
	springPackage = ftypes.Package{
		ID:      "org.springframework.boot:spring-boot:2.6.0",
		Name:    "org.springframework.boot:spring-boot",
		Version: "2.6.0",
		Identifier: ftypes.PkgIdentifier{
			UID:    "01",
			BOMRef: "pkg:maven/org.springframework.boot/spring-boot@2.6.0",
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeMaven,
				Namespace: "org.springframework.boot",
				Name:      "spring-boot",
				Version:   "2.6.0",
			},
		},
	}
	bashPackage = ftypes.Package{
		ID:      "bash@5.3",
		Name:    "bash",
		Version: "5.3",
		Identifier: ftypes.PkgIdentifier{
			UID: "02",
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeDebian,
				Namespace: "debian",
				Name:      "bash",
				Version:   "5.3",
			},
		},
	}
	goModulePackage = ftypes.Package{
		ID:           "github.com/aquasecurity/go-module@v1.0.0",
		Name:         "github.com/aquasecurity/go-module",
		Version:      "v1.0.0",
		Relationship: ftypes.RelationshipRoot,
		Identifier: ftypes.PkgIdentifier{
			UID: "03",
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeGolang,
				Namespace: "github.com/aquasecurity",
				Name:      "go-module",
				Version:   "v1.0.0",
			},
		},
	}
	goDirectPackage1 = ftypes.Package{
		ID:           "github.com/aquasecurity/go-direct1@v2.0.0",
		Name:         "github.com/aquasecurity/go-direct1",
		Version:      "v2.0.0",
		Relationship: ftypes.RelationshipDirect,
		Identifier: ftypes.PkgIdentifier{
			UID: "04",
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeGolang,
				Namespace: "github.com/aquasecurity",
				Name:      "go-direct1",
				Version:   "v2.0.0",
			},
		},
	}
	goDirectPackage2 = ftypes.Package{
		ID:           "github.com/aquasecurity/go-direct2@v3.0.0",
		Name:         "github.com/aquasecurity/go-direct2",
		Version:      "v3.0.0",
		Relationship: ftypes.RelationshipDirect,
		Identifier: ftypes.PkgIdentifier{
			UID: "05",
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeGolang,
				Namespace: "github.com/aquasecurity",
				Name:      "go-direct2",
				Version:   "v3.0.0",
			},
		},
	}
	goTransitivePackage = ftypes.Package{
		ID:           "github.com/aquasecurity/go-transitive@v4.0.0",
		Name:         "github.com/aquasecurity/go-transitive",
		Version:      "v4.0.0",
		Relationship: ftypes.RelationshipIndirect,
		Identifier: ftypes.PkgIdentifier{
			UID: "06",
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeGolang,
				Namespace: "github.com/aquasecurity",
				Name:      "go-transitive",
				Version:   "v4.0.0",
			},
		},
	}
	vuln1 = types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2021-44228",
		PkgName:          springPackage.Name,
		InstalledVersion: springPackage.Version,
		PkgIdentifier:    springPackage.Identifier,
	}
	vuln2 = types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2021-0001",
		PkgName:          springPackage.Name,
		InstalledVersion: springPackage.Version,
		PkgIdentifier:    springPackage.Identifier,
	}
	vuln3 = types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2022-3715",
		PkgName:          bashPackage.Name,
		InstalledVersion: bashPackage.Version,
		PkgIdentifier:    bashPackage.Identifier,
	}
	vuln4 = types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2024-10000",
		PkgName:          bashPackage.Name,
		InstalledVersion: bashPackage.Version,
		PkgIdentifier:    bashPackage.Identifier,
	}
	vuln5 = types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2024-0001",
		PkgName:          goTransitivePackage.Name,
		InstalledVersion: goTransitivePackage.Version,
		PkgIdentifier:    goTransitivePackage.Identifier,
	}
)

func TestMain(m *testing.M) {
	log.InitLogger(false, true)
	os.Exit(m.Run())
}

func TestFilter(t *testing.T) {
	// Set up the OCI registry
	tr, d := setUpRegistry(t)

	type args struct {
		report *types.Report
		opts   vex.Options
	}
	tests := []struct {
		name    string
		setup   func(t *testing.T, tmpDir string)
		args    args
		want    *types.Report
		wantErr string
	}{
		{
			name: "OpenVEX",
			args: args{
				// - oci:debian?tag=12
				//     - pkg:maven/org.springframework.boot/spring-boot@2.6.0
				report: imageReport([]types.Result{
					springResult(types.Result{
						Vulnerabilities: []types.DetectedVulnerability{vuln1},
					}),
				}),
				opts: vex.Options{
					Sources: []vex.Source{
						{
							Type:     vex.TypeFile,
							FilePath: "testdata/openvex.json",
						},
					},
				},
			},
			want: imageReport([]types.Result{
				springResult(types.Result{
					Vulnerabilities:  []types.DetectedVulnerability{},
					ModifiedFindings: []types.ModifiedFinding{modifiedFinding(vuln1, vulnerableCodeNotInExecutePath, "testdata/openvex.json")},
				}),
			}),
		},
		{
			name: "OpenVEX, multiple statements",
			args: args{
				// - oci:debian?tag=12
				//     - pkg:maven/org.springframework.boot/spring-boot@2.6.0
				report: imageReport([]types.Result{
					springResult(types.Result{
						Vulnerabilities: []types.DetectedVulnerability{
							vuln1, // filtered by VEX
							vuln2,
						},
					}),
				}),
				opts: vex.Options{
					Sources: []vex.Source{
						{
							Type:     vex.TypeFile,
							FilePath: "testdata/openvex-multiple.json",
						},
					},
				},
			},
			want: imageReport([]types.Result{
				springResult(types.Result{
					Vulnerabilities:  []types.DetectedVulnerability{vuln2},
					ModifiedFindings: []types.ModifiedFinding{modifiedFinding(vuln1, vulnerableCodeNotInExecutePath, "testdata/openvex-multiple.json")},
				}),
			}),
		},
		{
			name: "OpenVEX, subcomponents, oci image",
			args: args{
				// - oci:debian?tag=12
				//     - pkg:deb/debian/bash@5.3
				report: imageReport([]types.Result{
					bashResult(types.Result{
						Vulnerabilities: []types.DetectedVulnerability{
							vuln3, // filtered by VEX
						},
					}),
				}),
				opts: vex.Options{
					Sources: []vex.Source{
						{
							Type:     vex.TypeFile,
							FilePath: "testdata/openvex-oci.json",
						},
					},
				},
			},
			want: imageReport([]types.Result{
				bashResult(types.Result{
					Vulnerabilities:  []types.DetectedVulnerability{},
					ModifiedFindings: []types.ModifiedFinding{modifiedFinding(vuln3, vulnerableCodeNotInExecutePath, "testdata/openvex-oci.json")},
				}),
			}),
		},
		{
			name: "OpenVEX, subcomponents, mismatched oci image",
			args: args{
				report: imageReport(types.Results{
					bashResult(types.Result{
						Vulnerabilities: []types.DetectedVulnerability{vuln3},
					}),
				}),
				opts: vex.Options{
					Sources: []vex.Source{
						{
							Type:     vex.TypeFile,
							FilePath: "testdata/openvex-oci-mismatch.json",
						},
					},
				},
			},
			want: imageReport([]types.Result{
				bashResult(types.Result{
					Vulnerabilities: []types.DetectedVulnerability{vuln3},
				}),
			}),
		},
		{
			name: "OpenVEX, single path between product and subcomponent",
			args: args{
				report: fsReport([]types.Result{
					goSinglePathResult(types.Result{
						Vulnerabilities: []types.DetectedVulnerability{
							vuln5, // filtered by VEX
						},
					}),
				}),
				opts: vex.Options{
					Sources: []vex.Source{
						{
							Type:     vex.TypeFile,
							FilePath: "testdata/openvex-nested.json",
						},
					},
				},
			},
			want: fsReport([]types.Result{
				goSinglePathResult(types.Result{
					Vulnerabilities:  []types.DetectedVulnerability{},
					ModifiedFindings: []types.ModifiedFinding{modifiedFinding(vuln5, vulnerableCodeNotInExecutePath, "testdata/openvex-nested.json")},
				}),
			}),
		},
		{
			name: "OpenVEX, multi paths between product and subcomponent",
			args: args{
				report: fsReport([]types.Result{
					goMultiPathResult(types.Result{
						Vulnerabilities: []types.DetectedVulnerability{
							vuln5,
						},
					}),
				}),
				opts: vex.Options{
					Sources: []vex.Source{
						{
							Type:     vex.TypeFile,
							FilePath: "testdata/openvex-nested.json",
						},
					},
				},
			},
			want: fsReport([]types.Result{
				goMultiPathResult(types.Result{
					Vulnerabilities: []types.DetectedVulnerability{vuln5}, // Will not be filtered because of multi paths
				}),
			}),
		},
		{
			name: "CycloneDX SBOM with CycloneDX VEX",
			args: args{
				report: &types.Report{
					ArtifactType: artifact.TypeCycloneDX,
					BOM: &core.BOM{
						SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
						Version:      1,
					},
					Results: []types.Result{
						springResult(types.Result{
							Vulnerabilities: []types.DetectedVulnerability{vuln1},
						}),
					},
				},
				opts: vex.Options{
					Sources: []vex.Source{
						{
							Type:     vex.TypeFile,
							FilePath: "testdata/cyclonedx.json",
						},
					},
				},
			},
			want: &types.Report{
				ArtifactType: artifact.TypeCycloneDX,
				BOM: &core.BOM{
					SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
					Version:      1,
				},
				Results: []types.Result{
					springResult(types.Result{
						Vulnerabilities:  []types.DetectedVulnerability{},
						ModifiedFindings: []types.ModifiedFinding{modifiedFinding(vuln1, codeNotReachable, "CycloneDX VEX")},
					}),
				},
			},
		},
		{
			name: "CycloneDX VEX wrong URN",
			args: args{
				report: &types.Report{
					ArtifactType: artifact.TypeCycloneDX,
					BOM: &core.BOM{
						SerialNumber: "urn:uuid:wrong",
						Version:      1,
					},
					Results: []types.Result{
						springResult(types.Result{
							Vulnerabilities: []types.DetectedVulnerability{vuln1},
						}),
					},
				},
				opts: vex.Options{
					Sources: []vex.Source{
						{
							Type:     vex.TypeFile,
							FilePath: "testdata/cyclonedx.json",
						},
					},
				},
			},
			want: &types.Report{
				ArtifactType: artifact.TypeCycloneDX,
				BOM: &core.BOM{
					SerialNumber: "urn:uuid:wrong",
					Version:      1,
				},
				Results: []types.Result{
					springResult(types.Result{
						Vulnerabilities: []types.DetectedVulnerability{vuln1},
					}),
				},
			},
		},
		{
			name: "CSAF, not affected",
			args: args{
				report: imageReport([]types.Result{
					goSinglePathResult(types.Result{
						Vulnerabilities: []types.DetectedVulnerability{
							vuln5, // filtered by VEX
						},
					}),
				}),
				opts: vex.Options{
					Sources: []vex.Source{
						{
							Type:     vex.TypeFile,
							FilePath: "testdata/csaf.json",
						},
					},
				},
			},
			want: imageReport([]types.Result{
				goSinglePathResult(types.Result{
					Vulnerabilities:  []types.DetectedVulnerability{},
					ModifiedFindings: []types.ModifiedFinding{modifiedFinding(vuln5, vulnerableCodeNotInExecutePath, "testdata/csaf.json")},
				}),
			}),
		},
		{
			name: "CSAF with relationships, not affected",
			args: args{
				report: imageReport([]types.Result{
					goSinglePathResult(types.Result{
						Vulnerabilities: []types.DetectedVulnerability{
							vuln5, // filtered by VEX
						},
					}),
				}),
				opts: vex.Options{
					Sources: []vex.Source{
						{
							Type:     vex.TypeFile,
							FilePath: "testdata/csaf-relationships.json",
						},
					},
				},
			},
			want: imageReport([]types.Result{
				goSinglePathResult(types.Result{
					Vulnerabilities:  []types.DetectedVulnerability{},
					ModifiedFindings: []types.ModifiedFinding{modifiedFinding(vuln5, vulnerableCodeNotInExecutePath, "testdata/csaf-relationships.json")},
				}),
			}),
		},
		{
			name: "CSAF with relationships, affected",
			args: args{
				report: imageReport([]types.Result{
					goMultiPathResult(types.Result{
						Vulnerabilities: []types.DetectedVulnerability{
							vuln5,
						},
					}),
				}),
				opts: vex.Options{
					Sources: []vex.Source{
						{
							Type:     vex.TypeFile,
							FilePath: "testdata/csaf-relationships.json",
						},
					},
				},
			},
			want: imageReport([]types.Result{
				goMultiPathResult(types.Result{
					Vulnerabilities: []types.DetectedVulnerability{vuln5}, // Will not be filtered because of multi paths
				}),
			}),
		},
		{
			name: "VEX Repository",
			setup: func(t *testing.T, tmpDir string) {
				// Create repository.yaml
				vexDir := filepath.Join(tmpDir, ".trivy", "vex")
				require.NoError(t, os.MkdirAll(vexDir, 0755))

				configPath := filepath.Join(vexDir, "repository.yaml")
				configContent := `
repositories:
  - name: default
    url: https://example.com/vex/default
    enabled: true`
				require.NoError(t, os.WriteFile(configPath, []byte(configContent), 0644))
			},
			args: args{
				report: imageReport([]types.Result{
					bashResult(types.Result{
						Vulnerabilities: []types.DetectedVulnerability{
							vuln3, // filtered by VEX
						},
					}),
				}),
				opts: vex.Options{
					CacheDir: "testdata/single-repo",
					Sources:  []vex.Source{{Type: vex.TypeRepository}},
				},
			},
			want: imageReport([]types.Result{
				bashResult(types.Result{
					Vulnerabilities: []types.DetectedVulnerability{},
					ModifiedFindings: []types.ModifiedFinding{
						modifiedFinding(vuln3, "vulnerable_code_not_in_execute_path", "VEX Repository: default (https://example.com/vex/default)"),
					},
				}),
			}),
		},
		{
			name: "VEX attestation from OCI registry",
			args: args{
				// - oci:debian?tag=12
				//     - pkg:deb/debian/bash@5.3
				report: imageReportWithAttestation([]types.Result{
					bashResult(types.Result{
						Vulnerabilities: []types.DetectedVulnerability{
							vuln3, // filtered by VEX
						},
					}),
				}, fmt.Sprintf("%s/debian@%s", strings.TrimPrefix(tr.URL, "http://"), d.String())),
				opts: vex.Options{
					Sources: []vex.Source{
						{Type: vex.TypeOCI},
					},
				},
			},
			want: imageReportWithAttestation([]types.Result{
				bashResult(types.Result{
					Vulnerabilities: []types.DetectedVulnerability{},
					ModifiedFindings: []types.ModifiedFinding{
						modifiedFinding(vuln3, vulnerableCodeNotInExecutePath,
							fmt.Sprintf("VEX attestation in OCI registry (%s)", ociPURLString(tr, d))),
					},
				}),
			}, fmt.Sprintf("%s/debian@%s", strings.TrimPrefix(tr.URL, "http://"), d.String())),
		},
		{
			name: "unknown format",
			args: args{
				report: &types.Report{},
				opts: vex.Options{
					Sources: []vex.Source{
						{
							Type:     vex.TypeFile,
							FilePath: "testdata/unknown.json",
						},
					},
				},
			},
			wantErr: "unable to load VEX",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			t.Setenv("XDG_DATA_HOME", tmpDir)
			if tt.setup != nil {
				tt.setup(t, tmpDir)
			}
			err := vex.Filter(context.Background(), tt.args.report, tt.args.opts)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, tt.args.report)
		})
	}
}

func imageReport(results types.Results) *types.Report {
	return &types.Report{
		ArtifactName: "debian:12",
		ArtifactType: artifact.TypeContainerImage,
		Metadata: types.Metadata{
			RepoDigests: []string{
				"debian@sha256:4482958b4461ff7d9fabc24b3a9ab1e9a2c85ece07b2db1840c7cbc01d053e90",
			},
			ImageConfig: v1.ConfigFile{
				Architecture: "amd64",
			},
		},
		Results: results,
	}
}

func imageReportWithAttestation(results types.Results, repoDigest string) *types.Report {
	report := imageReport(results)
	report.Metadata.RepoDigests[0] = repoDigest
	return report
}

func ociPURLString(ts *httptest.Server, d v1.Hash) string {
	p := &packageurl.PackageURL{
		Type:    packageurl.TypeOCI,
		Name:    "debian",
		Version: d.String(),
		Qualifiers: packageurl.Qualifiers{
			{
				Key:   "arch",
				Value: "amd64",
			},
			{
				Key:   "repository_url",
				Value: strings.TrimPrefix(ts.URL, "http://") + "/debian",
			},
		},
	}
	return p.String()
}

func fsReport(results types.Results) *types.Report {
	return &types.Report{
		ArtifactName: ".",
		ArtifactType: artifact.TypeFilesystem,
		Results:      results,
	}
}

func springResult(result types.Result) types.Result {
	result.Type = ftypes.Jar
	result.Class = types.ClassLangPkg
	result.Packages = []ftypes.Package{springPackage}
	return result
}

// bashResult wraps the result with the bash package
func bashResult(result types.Result) types.Result {
	result.Type = ftypes.Debian
	result.Class = types.ClassOSPkg
	result.Packages = []ftypes.Package{bashPackage}
	return result
}

func goSinglePathResult(result types.Result) types.Result {
	result.Type = ftypes.GoModule
	result.Class = types.ClassLangPkg

	// - pkg:golang/github.com/aquasecurity/go-module@v1.0.0
	//     - pkg:golang/github.com/aquasecurity/go-direct1@v2.0.0
	//         - pkg:golang/github.com/aquasecurity/go-transitive@v4.0.0
	goModule := clonePackage(goModulePackage)
	goDirect1 := clonePackage(goDirectPackage1)
	goTransitive := clonePackage(goTransitivePackage)

	goModule.DependsOn = []string{goDirect1.ID}
	goDirect1.DependsOn = []string{goTransitive.ID}
	result.Packages = []ftypes.Package{
		goModule,
		goDirect1,
		goTransitive,
	}
	return result
}

func goMultiPathResult(result types.Result) types.Result {
	result.Type = ftypes.GoModule
	result.Class = types.ClassLangPkg

	// - pkg:golang/github.com/aquasecurity/go-module@v2.0.0
	//     - pkg:golang/github.com/aquasecurity/go-direct1@v3.0.0
	//         - pkg:golang/github.com/aquasecurity/go-transitive@v5.0.0
	//     - pkg:golang/github.com/aquasecurity/go-direct2@v4.0.0
	//         - pkg:golang/github.com/aquasecurity/go-transitive@v5.0.0
	goModule := clonePackage(goModulePackage)
	goDirect1 := clonePackage(goDirectPackage1)
	goDirect2 := clonePackage(goDirectPackage2)
	goTransitive := clonePackage(goTransitivePackage)

	goModule.DependsOn = []string{
		goDirect1.ID,
		goDirect2.ID,
	}
	goDirect1.DependsOn = []string{goTransitive.ID}
	goDirect2.DependsOn = []string{goTransitive.ID}
	result.Packages = []ftypes.Package{
		goModule,
		goDirect1,
		goDirect2,
		goTransitive,
	}
	return result
}

func modifiedFinding(vuln types.DetectedVulnerability, statement, source string) types.ModifiedFinding {
	return types.ModifiedFinding{
		Type:      types.FindingTypeVulnerability,
		Status:    types.FindingStatusNotAffected,
		Statement: statement,
		Source:    source,
		Finding:   vuln,
	}
}

func clonePackage(p ftypes.Package) ftypes.Package {
	n := p
	n.DependsOn = []string{}
	return n
}
