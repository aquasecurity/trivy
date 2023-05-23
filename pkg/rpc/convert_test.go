package rpc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/rpc/common"
	"github.com/aquasecurity/trivy/rpc/scanner"
)

func TestConvertToRpcPkgs(t *testing.T) {
	type args struct {
		pkgs []ftypes.Package
	}
	tests := []struct {
		name string
		args args
		want []*common.Package
	}{
		{
			name: "happy path",
			args: args{
				pkgs: []ftypes.Package{
					{
						Name:       "binary",
						Version:    "1.2.3",
						Release:    "1",
						Epoch:      2,
						Arch:       "x86_64",
						SrcName:    "src",
						SrcVersion: "1.2.3",
						SrcRelease: "1",
						SrcEpoch:   2,
						Licenses:   []string{"MIT"},
						Layer: ftypes.Layer{
							Digest: "sha256:6a428f9f83b0a29f1fdd2ccccca19a9bab805a925b8eddf432a5a3d3da04afbc",
							DiffID: "sha256:39982b2a789afc156fff00c707d0ff1c6ab4af8f1666a8df4787714059ce24e7",
						},
						Digest: "SHA1:901a7b55410321c4d35543506cff2a8613ef5aa2",
					},
				},
			},
			want: []*common.Package{
				{
					Name:       "binary",
					Version:    "1.2.3",
					Release:    "1",
					Epoch:      2,
					Arch:       "x86_64",
					SrcName:    "src",
					SrcVersion: "1.2.3",
					SrcRelease: "1",
					SrcEpoch:   2,
					Licenses:   []string{"MIT"},
					Layer: &common.Layer{
						Digest: "sha256:6a428f9f83b0a29f1fdd2ccccca19a9bab805a925b8eddf432a5a3d3da04afbc",
						DiffId: "sha256:39982b2a789afc156fff00c707d0ff1c6ab4af8f1666a8df4787714059ce24e7",
					},
					Digest: "SHA1:901a7b55410321c4d35543506cff2a8613ef5aa2",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertToRPCPkgs(tt.args.pkgs)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}

func TestConvertFromRpcPkgs(t *testing.T) {
	type args struct {
		rpcPkgs []*common.Package
	}
	tests := []struct {
		name string
		args args
		want []ftypes.Package
	}{
		{
			args: args{
				rpcPkgs: []*common.Package{
					{
						Name:       "binary",
						Version:    "1.2.3",
						Release:    "1",
						Epoch:      2,
						Arch:       "x86_64",
						SrcName:    "src",
						SrcVersion: "1.2.3",
						SrcRelease: "1",
						SrcEpoch:   2,
						Licenses:   []string{"MIT"},
						Layer: &common.Layer{
							Digest: "sha256:6a428f9f83b0a29f1fdd2ccccca19a9bab805a925b8eddf432a5a3d3da04afbc",
							DiffId: "sha256:39982b2a789afc156fff00c707d0ff1c6ab4af8f1666a8df4787714059ce24e7",
						},
						Digest: "SHA1:901a7b55410321c4d35543506cff2a8613ef5aa2",
					},
				},
			},
			want: []ftypes.Package{
				{
					Name:       "binary",
					Version:    "1.2.3",
					Release:    "1",
					Epoch:      2,
					Arch:       "x86_64",
					SrcName:    "src",
					SrcVersion: "1.2.3",
					SrcRelease: "1",
					SrcEpoch:   2,
					Licenses:   []string{"MIT"},
					Layer: ftypes.Layer{
						Digest: "sha256:6a428f9f83b0a29f1fdd2ccccca19a9bab805a925b8eddf432a5a3d3da04afbc",
						DiffID: "sha256:39982b2a789afc156fff00c707d0ff1c6ab4af8f1666a8df4787714059ce24e7",
					},
					Digest: "SHA1:901a7b55410321c4d35543506cff2a8613ef5aa2",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertFromRPCPkgs(tt.args.rpcPkgs)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}

func TestConvertToRpcVulns(t *testing.T) {
	fixedPublishedDate := time.Unix(1257894000, 0)
	fixedLastModifiedDate := time.Unix(1257894010, 0)

	type args struct {
		vulns []types.DetectedVulnerability
	}
	tests := []struct {
		name string
		args args
		want []*common.Vulnerability
	}{
		{
			name: "happy path",
			args: args{
				vulns: []types.DetectedVulnerability{
					{
						VulnerabilityID:  "CVE-2019-0001",
						PkgName:          "foo",
						InstalledVersion: "1.2.3",
						FixedVersion:     "1.2.4",
						Vulnerability: dbTypes.Vulnerability{
							Title:       "DoS",
							Description: "Denial of Service",
							Severity:    "MEDIUM",
							VendorSeverity: dbTypes.VendorSeverity{
								vulnerability.RedHat: dbTypes.SeverityMedium,
							},
							CVSS: dbTypes.VendorCVSS{
								vulnerability.RedHat: {
									V2Vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C",
									V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
									V2Score:  7.2,
									V3Score:  7.8,
								},
							},
							References:       []string{"http://example.com"},
							PublishedDate:    &fixedPublishedDate,
							LastModifiedDate: &fixedLastModifiedDate,
						},
						Layer: ftypes.Layer{
							Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
							DiffID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
						},
						PrimaryURL: "https://avd.aquasec.com/nvd/CVE-2019-0001",
						DataSource: &dbTypes.DataSource{
							Name: "GitHub Security Advisory Maven",
							URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
						},
					},
				},
			},
			want: []*common.Vulnerability{
				{
					VulnerabilityId:  "CVE-2019-0001",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "1.2.4",
					Title:            "DoS",
					Description:      "Denial of Service",
					Severity:         common.Severity_MEDIUM,
					VendorSeverity: map[string]common.Severity{
						string(vulnerability.RedHat): common.Severity_MEDIUM,
					},
					Cvss: map[string]*common.CVSS{
						"redhat": {
							V2Vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C",
							V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
							V2Score:  7.2,
							V3Score:  7.8,
						},
					},
					References: []string{"http://example.com"},
					Layer: &common.Layer{
						Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
						DiffId: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
					},
					PrimaryUrl:       "https://avd.aquasec.com/nvd/CVE-2019-0001",
					PublishedDate:    timestamppb.New(fixedPublishedDate),
					LastModifiedDate: timestamppb.New(fixedLastModifiedDate),
					DataSource: &common.DataSource{
						Name: "GitHub Security Advisory Maven",
						Url:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
					},
				},
			},
		},
		{
			name: "invalid severity",
			args: args{
				vulns: []types.DetectedVulnerability{
					{
						VulnerabilityID:  "CVE-2019-0002",
						PkgName:          "bar",
						InstalledVersion: "1.2.3",
						FixedVersion:     "1.2.4",
						Vulnerability: dbTypes.Vulnerability{
							Title:       "DoS",
							Description: "Denial of Service",
							Severity:    "INVALID",
							References:  []string{"http://example.com"},
						},
						Layer: ftypes.Layer{
							Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
							DiffID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
						},
						DataSource: &dbTypes.DataSource{
							Name: "GitHub Security Advisory Maven",
							URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
						},
					},
				},
			},
			want: []*common.Vulnerability{
				{
					VulnerabilityId:  "CVE-2019-0002",
					PkgName:          "bar",
					InstalledVersion: "1.2.3",
					FixedVersion:     "1.2.4",
					Title:            "DoS",
					Description:      "Denial of Service",
					Severity:         common.Severity_UNKNOWN,
					VendorSeverity:   make(map[string]common.Severity),
					Cvss:             make(map[string]*common.CVSS),
					References:       []string{"http://example.com"},
					Layer: &common.Layer{
						Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
						DiffId: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
					},
					DataSource: &common.DataSource{
						Name: "GitHub Security Advisory Maven",
						Url:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertToRPCVulns(tt.args.vulns)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}

func TestConvertFromRPCResults(t *testing.T) {
	fixedPublishedDate := time.Date(2009, 11, 10, 23, 0, 0, 0, time.UTC)
	fixedLastModifiedDate := time.Date(2009, 11, 10, 23, 0, 10, 0, time.UTC)

	type args struct {
		rpcResults []*scanner.Result
	}
	tests := []struct {
		name string
		args args
		want []types.Result
	}{
		{
			name: "happy path",
			args: args{rpcResults: []*scanner.Result{
				{
					Target: "alpine:3.10",
					Type:   fos.Alpine,
					Vulnerabilities: []*common.Vulnerability{
						{
							VulnerabilityId:  "CVE-2019-0001",
							PkgName:          "musl",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Title:            "DoS",
							Description:      "Denial of Service",
							Severity:         common.Severity_MEDIUM,
							SeveritySource:   string(vulnerability.NVD),
							CweIds:           []string{"CWE-123", "CWE-456"},
							VendorSeverity: map[string]common.Severity{
								string(vulnerability.RedHat): common.Severity_MEDIUM,
							},
							Cvss: map[string]*common.CVSS{
								string(vulnerability.RedHat): {
									V2Vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C",
									V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
									V2Score:  7.2,
									V3Score:  7.8,
								},
							},
							References: []string{"http://example.com"},
							Layer: &common.Layer{
								Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
								DiffId: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
							},
							PrimaryUrl:       "https://avd.aquasec.com/nvd/CVE-2019-0001",
							PublishedDate:    timestamppb.New(fixedPublishedDate),
							LastModifiedDate: timestamppb.New(fixedLastModifiedDate),
							DataSource: &common.DataSource{
								Name: "GitHub Security Advisory Maven",
								Url:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
							},
						},
					},
				}},
			},
			want: []types.Result{
				{
					Target: "alpine:3.10",
					Type:   fos.Alpine,
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2019-0001",
							PkgName:          "musl",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Layer: ftypes.Layer{
								Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
								DiffID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
							},
							SeveritySource: vulnerability.NVD,
							PrimaryURL:     "https://avd.aquasec.com/nvd/CVE-2019-0001",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "DoS",
								Description: "Denial of Service",
								Severity:    common.Severity_MEDIUM.String(),
								VendorSeverity: dbTypes.VendorSeverity{
									vulnerability.RedHat: dbTypes.SeverityMedium,
								},
								CweIDs: []string{"CWE-123", "CWE-456"},
								CVSS: dbTypes.VendorCVSS{
									vulnerability.RedHat: {
										V2Vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C",
										V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
										V2Score:  7.2,
										V3Score:  7.8,
									},
								},
								References:       []string{"http://example.com"},
								PublishedDate:    &fixedPublishedDate,
								LastModifiedDate: &fixedLastModifiedDate,
							},
							DataSource: &dbTypes.DataSource{
								Name: "GitHub Security Advisory Maven",
								URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
							},
						},
					},
				},
			},
		},
		{
			name: "happy path - with nil dates",
			args: args{rpcResults: []*scanner.Result{
				{
					Target: "alpine:3.10",
					Type:   fos.Alpine,
					Vulnerabilities: []*common.Vulnerability{
						{
							VulnerabilityId:  "CVE-2019-0001",
							PkgName:          "musl",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Title:            "DoS",
							Description:      "Denial of Service",
							Severity:         common.Severity_MEDIUM,
							SeveritySource:   string(vulnerability.NVD),
							CweIds:           []string{"CWE-123", "CWE-456"},
							Cvss: map[string]*common.CVSS{
								"redhat": {
									V2Vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C",
									V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
									V2Score:  7.2,
									V3Score:  7.8,
								},
							},
							References: []string{"http://example.com"},
							Layer: &common.Layer{
								Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
								DiffId: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
							},
							PrimaryUrl:       "https://avd.aquasec.com/nvd/CVE-2019-0001",
							PublishedDate:    nil,
							LastModifiedDate: nil,
						},
					},
				}},
			},
			want: []types.Result{
				{
					Target: "alpine:3.10",
					Type:   fos.Alpine,
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2019-0001",
							PkgName:          "musl",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Layer: ftypes.Layer{
								Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
								DiffID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
							},
							SeveritySource: vulnerability.NVD,
							PrimaryURL:     "https://avd.aquasec.com/nvd/CVE-2019-0001",
							Vulnerability: dbTypes.Vulnerability{
								Title:          "DoS",
								Description:    "Denial of Service",
								Severity:       common.Severity_MEDIUM.String(),
								CweIDs:         []string{"CWE-123", "CWE-456"},
								VendorSeverity: make(dbTypes.VendorSeverity),
								CVSS: dbTypes.VendorCVSS{
									vulnerability.RedHat: {
										V2Vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C",
										V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
										V2Score:  7.2,
										V3Score:  7.8,
									},
								},
								References: []string{"http://example.com"},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertFromRPCResults(tt.args.rpcResults)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}
