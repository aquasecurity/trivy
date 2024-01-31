package vex_test

import (
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
			name: "OpenVEX, multiple statements",
			fields: fields{
				filePath: "testdata/openvex-multiple.json",
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
					{
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
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
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
				},
			},
		},
		{
			name: "CycloneDX SBOM with CycloneDX VEX",
			fields: fields{
				filePath: "testdata/cyclonedx.json",
				report: types.Report{
					CycloneDX: &ftypes.CycloneDX{
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
					CycloneDX: &ftypes.CycloneDX{
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
			assert.Equal(t, tt.want, v.Filter(tt.args.vulns))
		})
	}
}
