package rpc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
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
						Locations: []ftypes.Location{
							{
								StartLine: 10,
								EndLine:   20,
							},
							{
								StartLine: 22,
								EndLine:   32,
							},
						},
						Layer: ftypes.Layer{
							Digest: "sha256:6a428f9f83b0a29f1fdd2ccccca19a9bab805a925b8eddf432a5a3d3da04afbc",
							DiffID: "sha256:39982b2a789afc156fff00c707d0ff1c6ab4af8f1666a8df4787714059ce24e7",
						},
						Digest:   "SHA1:901a7b55410321c4d35543506cff2a8613ef5aa2",
						Indirect: true,
						Identifier: ftypes.PkgIdentifier{
							UID: "01",
						},
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
					Locations: []*common.Location{
						{
							StartLine: 10,
							EndLine:   20,
						},
						{
							StartLine: 22,
							EndLine:   32,
						},
					},
					Layer: &common.Layer{
						Digest: "sha256:6a428f9f83b0a29f1fdd2ccccca19a9bab805a925b8eddf432a5a3d3da04afbc",
						DiffId: "sha256:39982b2a789afc156fff00c707d0ff1c6ab4af8f1666a8df4787714059ce24e7",
					},
					Digest:   "SHA1:901a7b55410321c4d35543506cff2a8613ef5aa2",
					Indirect: true,
					Identifier: &common.PkgIdentifier{
						Uid: "01",
					},
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
						Locations: []*common.Location{
							{
								StartLine: 10,
								EndLine:   20,
							},
							{
								StartLine: 22,
								EndLine:   32,
							},
						},
						Layer: &common.Layer{
							Digest: "sha256:6a428f9f83b0a29f1fdd2ccccca19a9bab805a925b8eddf432a5a3d3da04afbc",
							DiffId: "sha256:39982b2a789afc156fff00c707d0ff1c6ab4af8f1666a8df4787714059ce24e7",
						},
						Digest:   "SHA1:901a7b55410321c4d35543506cff2a8613ef5aa2",
						Indirect: true,
						Identifier: &common.PkgIdentifier{
							Uid: "01",
						},
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
					Locations: []ftypes.Location{
						{
							StartLine: 10,
							EndLine:   20,
						},
						{
							StartLine: 22,
							EndLine:   32,
						},
					},
					Layer: ftypes.Layer{
						Digest: "sha256:6a428f9f83b0a29f1fdd2ccccca19a9bab805a925b8eddf432a5a3d3da04afbc",
						DiffID: "sha256:39982b2a789afc156fff00c707d0ff1c6ab4af8f1666a8df4787714059ce24e7",
					},
					Digest:   "SHA1:901a7b55410321c4d35543506cff2a8613ef5aa2",
					Indirect: true,
					Identifier: ftypes.PkgIdentifier{
						UID: "01",
					},
				},
			},
		},
		{
			args: args{
				rpcPkgs: []*common.Package{
					{
						Name:       "binary",
						Version:    "4.2+dfsg",
						Release:    "0.1+deb7u4",
						Epoch:      0,
						Arch:       "amd64",
						SrcName:    "bash",
						SrcVersion: "4.2+dfsg",
						SrcRelease: "0.1+deb7u4",
						SrcEpoch:   0,
						Licenses:   []string{"GPL-3.0"},
						Locations: []*common.Location{
							{
								StartLine: 10,
								EndLine:   20,
							},
							{
								StartLine: 22,
								EndLine:   32,
							},
						},
						Layer: &common.Layer{
							Digest: "sha256:8d42b73fc1ddc2e9e66c954966f144665825e69f4ed10c66342ae7c26b38d4e4",
							DiffId: "sha256:745d171eb8c3d69f788da3a1b053056231ad140b80be71d6869229846a1f3a77",
						},
						Digest:   "SHA1:901a7b55410321c4d35543506cff2a8613ef5aa2",
						Indirect: false,
						Identifier: &common.PkgIdentifier{
							Uid: "63f8bef824b960e3",
						},
						Maintainer: "alice@example.com",
					},
				},
			},
			want: []ftypes.Package{
				{
					Name:       "binary",
					Version:    "4.2+dfsg",
					Release:    "0.1+deb7u4",
					Epoch:      0,
					Arch:       "amd64",
					SrcName:    "bash",
					SrcVersion: "4.2+dfsg",
					SrcRelease: "0.1+deb7u4",
					SrcEpoch:   0,
					Licenses:   []string{"GPL-3.0"},
					Locations: []ftypes.Location{
						{
							StartLine: 10,
							EndLine:   20,
						},
						{
							StartLine: 22,
							EndLine:   32,
						},
					},
					Layer: ftypes.Layer{
						Digest: "sha256:8d42b73fc1ddc2e9e66c954966f144665825e69f4ed10c66342ae7c26b38d4e4",
						DiffID: "sha256:745d171eb8c3d69f788da3a1b053056231ad140b80be71d6869229846a1f3a77",
					},
					Digest:   "SHA1:901a7b55410321c4d35543506cff2a8613ef5aa2",
					Indirect: false,
					Identifier: ftypes.PkgIdentifier{
						UID: "63f8bef824b960e3",
					},
					Maintainer: "alice@example.com",
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
								vulnerability.NVD: {
									V2Vector:  "AV:L/AC:L/Au:N/C:C/I:C/A:C",
									V3Vector:  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
									V40Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/U:Green",
									V2Score:   7.2,
									V3Score:   7.8,
									V40Score:  8.7,
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
						"nvd": {
							V2Vector:  "AV:L/AC:L/Au:N/C:C/I:C/A:C",
							V3Vector:  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
							V40Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/U:Green",
							V2Score:   7.2,
							V3Score:   7.8,
							V40Score:  8.7,
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
			args: args{
				rpcResults: []*scanner.Result{
					{
						Target: "alpine:3.10",
						Type:   string(ftypes.Alpine),
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
								CweIds: []string{
									"CWE-123",
									"CWE-456",
								},
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
					},
				},
			},
			want: []types.Result{
				{
					Target: "alpine:3.10",
					Type:   ftypes.Alpine,
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
								CweIDs: []string{
									"CWE-123",
									"CWE-456",
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
			args: args{
				rpcResults: []*scanner.Result{
					{
						Target: "alpine:3.10",
						Type:   string(ftypes.Alpine),
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
								CweIds: []string{
									"CWE-123",
									"CWE-456",
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
								PublishedDate:    nil,
								LastModifiedDate: nil,
							},
						},
					},
				},
			},
			want: []types.Result{
				{
					Target: "alpine:3.10",
					Type:   ftypes.Alpine,
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
								CweIDs: []string{
									"CWE-123",
									"CWE-456",
								},
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

func TestConvertFromRPCMisconfs(t *testing.T) {
	type args struct {
		misconfs []*common.DetectedMisconfiguration
	}
	tests := []struct {
		name string
		args args
		want []types.DetectedMisconfiguration
	}{
		{
			name: "happy path misconf",
			args: args{
				misconfs: []*common.DetectedMisconfiguration{
					{
						Type:        "Dockerfile Security Check",
						Id:          "DS005",
						AvdId:       "AVD-DS-0005",
						Title:       "ADD instead of COPY",
						Description: "You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.",
						Message:     "Consider using 'COPY . /app' command instead of 'ADD . /app'",
						Namespace:   "builtin.dockerfile.DS005",
						Query:       "data.builtin.dockerfile.DS005.deny",
						Resolution:  "Use COPY instead of ADD",
						Severity:    common.Severity_LOW,
						PrimaryUrl:  "https://avd.aquasec.com/misconfig/ds005",
						References: []string{
							"https://docs.docker.com/engine/reference/builder/#add",
							"https://avd.aquasec.com/misconfig/ds005",
						},
						Status: "FAIL",
						Layer:  &common.Layer{},
						CauseMetadata: &common.CauseMetadata{
							Provider:  "Dockerfile",
							Service:   "general",
							StartLine: 3,
							EndLine:   3,
							Code: &common.Code{
								Lines: []*common.Line{
									{
										Number:     3,
										Content:    "ADD . /app",
										IsCause:    true,
										Annotation: "",
										Truncated:  false,
										FirstCause: true,
										LastCause:  true,
									},
								},
							},
						},
					},
				},
			},
			want: []types.DetectedMisconfiguration{
				{
					Type:        "Dockerfile Security Check",
					ID:          "DS005",
					AVDID:       "AVD-DS-0005",
					Title:       "ADD instead of COPY",
					Description: "You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.",
					Message:     "Consider using 'COPY . /app' command instead of 'ADD . /app'",
					Namespace:   "builtin.dockerfile.DS005",
					Query:       "data.builtin.dockerfile.DS005.deny",
					Resolution:  "Use COPY instead of ADD",
					Severity:    "LOW",
					PrimaryURL:  "https://avd.aquasec.com/misconfig/ds005",
					References: []string{
						"https://docs.docker.com/engine/reference/builder/#add",
						"https://avd.aquasec.com/misconfig/ds005",
					},
					Status: "FAIL",
					Layer:  ftypes.Layer{},
					CauseMetadata: ftypes.CauseMetadata{
						Provider:  "Dockerfile",
						Service:   "general",
						StartLine: 3,
						EndLine:   3,
						Code: ftypes.Code{
							Lines: []ftypes.Line{
								{
									Number:     3,
									Content:    "ADD . /app",
									IsCause:    true,
									Annotation: "",
									Truncated:  false,
									FirstCause: true,
									LastCause:  true,
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertFromRPCMisconfs(tt.args.misconfs)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}

func TestConvertToRPCMiconfs(t *testing.T) {
	type args struct {
		misconfs []types.DetectedMisconfiguration
	}
	tests := []struct {
		name string
		args args
		want []*common.DetectedMisconfiguration
	}{
		{
			name: "happy path misconf",
			args: args{
				misconfs: []types.DetectedMisconfiguration{
					{
						Type:        "Dockerfile Security Check",
						ID:          "DS005",
						AVDID:       "AVD-DS-0005",
						Title:       "ADD instead of COPY",
						Description: "You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.",
						Message:     "Consider using 'COPY . /app' command instead of 'ADD . /app'",
						Namespace:   "builtin.dockerfile.DS005",
						Query:       "data.builtin.dockerfile.DS005.deny",
						Resolution:  "Use COPY instead of ADD",
						Severity:    "LOW",
						PrimaryURL:  "https://avd.aquasec.com/misconfig/ds005",
						References: []string{
							"https://docs.docker.com/engine/reference/builder/#add",
							"https://avd.aquasec.com/misconfig/ds005",
						},
						Status: "FAIL",
						Layer:  ftypes.Layer{},
						CauseMetadata: ftypes.CauseMetadata{
							Provider:  "Dockerfile",
							Service:   "general",
							StartLine: 3,
							EndLine:   3,
							Code: ftypes.Code{
								Lines: []ftypes.Line{
									{
										Number:     3,
										Content:    "ADD . /app",
										IsCause:    true,
										Annotation: "",
										Truncated:  false,
										FirstCause: true,
										LastCause:  true,
									},
								},
							},
						},
					},
				},
			},
			want: []*common.DetectedMisconfiguration{
				{
					Type:        "Dockerfile Security Check",
					Id:          "DS005",
					AvdId:       "AVD-DS-0005",
					Title:       "ADD instead of COPY",
					Description: "You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.",
					Message:     "Consider using 'COPY . /app' command instead of 'ADD . /app'",
					Namespace:   "builtin.dockerfile.DS005",
					Query:       "data.builtin.dockerfile.DS005.deny",
					Resolution:  "Use COPY instead of ADD",
					Severity:    common.Severity_LOW,
					PrimaryUrl:  "https://avd.aquasec.com/misconfig/ds005",
					References: []string{
						"https://docs.docker.com/engine/reference/builder/#add",
						"https://avd.aquasec.com/misconfig/ds005",
					},
					Status: "FAIL",
					Layer:  &common.Layer{},
					CauseMetadata: &common.CauseMetadata{
						Provider:  "Dockerfile",
						Service:   "general",
						StartLine: 3,
						EndLine:   3,
						Code: &common.Code{
							Lines: []*common.Line{
								{
									Number:     3,
									Content:    "ADD . /app",
									IsCause:    true,
									Annotation: "",
									Truncated:  false,
									FirstCause: true,
									LastCause:  true,
								},
							},
						},
						RenderedCause: &common.RenderedCause{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertToRPCMisconfs(tt.args.misconfs)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}

func TestConvertFromRPCLicenses(t *testing.T) {
	tests := []struct {
		name        string
		rpcLicenses []*common.DetectedLicense
		want        []types.DetectedLicense
	}{
		{
			name: "happy",
			rpcLicenses: []*common.DetectedLicense{
				{
					Severity:   common.Severity_HIGH,
					Category:   common.LicenseCategory_RESTRICTED,
					PkgName:    "alpine-baselayout",
					FilePath:   "some-path",
					Name:       "GPL-2.0",
					Text:       "text://* Permission to use this software in any way is granted without",
					Confidence: 1,
					Link:       "https://some-link",
				},
			},
			want: []types.DetectedLicense{
				{
					Severity:   "HIGH",
					Category:   "restricted",
					PkgName:    "alpine-baselayout",
					FilePath:   "some-path",
					Name:       "GPL-2.0",
					Text:       "text://* Permission to use this software in any way is granted without",
					Confidence: 1,
					Link:       "https://some-link",
				},
			},
		},
		{
			name:        "no licenses",
			rpcLicenses: nil,
			want:        nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertFromRPCDetectedLicenses(tt.rpcLicenses)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConvertToRPCLicenses(t *testing.T) {
	tests := []struct {
		name     string
		licenses []types.DetectedLicense
		want     []*common.DetectedLicense
	}{
		{
			name: "happy",
			licenses: []types.DetectedLicense{
				{
					Severity:   "HIGH",
					Category:   "restricted",
					PkgName:    "alpine-baselayout",
					FilePath:   "some-path",
					Name:       "GPL-2.0",
					Text:       "text://* Permission to use this software in any way is granted without",
					Confidence: 1,
					Link:       "https://some-link",
				},
			},
			want: []*common.DetectedLicense{
				{
					Severity:   common.Severity_HIGH,
					Category:   common.LicenseCategory_RESTRICTED,
					PkgName:    "alpine-baselayout",
					FilePath:   "some-path",
					Name:       "GPL-2.0",
					Text:       "text://* Permission to use this software in any way is granted without",
					Confidence: 1,
					Link:       "https://some-link",
				},
			},
		},
		{
			name:     "no licenses",
			licenses: nil,
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertToRPCLicenses(tt.licenses)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConvertToRPCLicenseCategory(t *testing.T) {
	tests := []struct {
		name     string
		category ftypes.LicenseCategory
		want     common.LicenseCategory_Enum
	}{
		{
			name:     "happy",
			category: ftypes.CategoryNotice,
			want:     common.LicenseCategory_NOTICE,
		},
		{
			name:     "unspecified",
			category: "",
			want:     common.LicenseCategory_UNSPECIFIED,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertToRPCLicenseCategory(tt.category)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConvertFromRPCLicenseCategory(t *testing.T) {
	tests := []struct {
		name        string
		rpcCategory common.LicenseCategory_Enum
		want        ftypes.LicenseCategory
	}{
		{
			name:        "happy",
			rpcCategory: common.LicenseCategory_RESTRICTED,
			want:        ftypes.CategoryRestricted,
		},
		{
			name:        "unspecified",
			rpcCategory: common.LicenseCategory_UNSPECIFIED,
			want:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertFromRPCLicenseCategory(tt.rpcCategory)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConvertToRPCLicenseType(t *testing.T) {
	tests := []struct {
		name string
		ty   ftypes.LicenseType
		want common.LicenseType_Enum
	}{
		{
			name: "happy",
			ty:   ftypes.LicenseTypeFile,
			want: common.LicenseType_LICENSE_FILE,
		},
		{
			name: "unspecified",
			ty:   "",
			want: common.LicenseType_UNSPECIFIED,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertToRPCLicenseType(tt.ty)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConvertFromRPCLicenseType(t *testing.T) {
	tests := []struct {
		name    string
		rpcType common.LicenseType_Enum
		want    ftypes.LicenseType
	}{
		{
			name:    "happy",
			rpcType: common.LicenseType_LICENSE_FILE,
			want:    ftypes.LicenseTypeFile,
		},
		{
			name:    "unspecified",
			rpcType: common.LicenseType_UNSPECIFIED,
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertFromRPCLicenseType(tt.rpcType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConvertToRPCLicenseFiles(t *testing.T) {
	tests := []struct {
		name         string
		licenseFiles []ftypes.LicenseFile
		want         []*common.LicenseFile
	}{
		{
			name: "happy",
			licenseFiles: []ftypes.LicenseFile{
				{
					Type:     ftypes.LicenseTypeFile,
					PkgName:  "alpine-baselayout",
					FilePath: "some-path",
					Findings: ftypes.LicenseFindings{
						{
							Category:   ftypes.CategoryRestricted,
							Name:       "GPL-2.0",
							Confidence: 1,
							Link:       "https://some-link",
						},
					},
					Layer: ftypes.Layer{
						Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
						DiffID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
					},
				},
			},
			want: []*common.LicenseFile{
				{
					LicenseType: common.LicenseType_LICENSE_FILE,
					PkgName:     "alpine-baselayout",
					FilePath:    "some-path",
					Fingings: []*common.LicenseFinding{
						{
							Category:   common.LicenseCategory_RESTRICTED,
							Name:       "GPL-2.0",
							Confidence: 1,
							Link:       "https://some-link",
						},
					},
					Layer: &common.Layer{
						Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
						DiffId: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ConvertToRPCLicenseFiles(tt.licenseFiles))
		})
	}
}

func TestConvertFromRPCLicenseFiles(t *testing.T) {
	tests := []struct {
		name         string
		licenseFiles []*common.LicenseFile
		want         []ftypes.LicenseFile
	}{
		{
			name: "happy",
			licenseFiles: []*common.LicenseFile{
				{
					LicenseType: common.LicenseType_LICENSE_FILE,
					PkgName:     "alpine-baselayout",
					FilePath:    "some-path",
					Fingings: []*common.LicenseFinding{
						{
							Category:   common.LicenseCategory_RESTRICTED,
							Name:       "GPL-2.0",
							Confidence: 1,
							Link:       "https://some-link",
						},
					},
					Layer: &common.Layer{
						Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
						DiffId: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
					},
				},
			},
			want: []ftypes.LicenseFile{
				{
					Type:     ftypes.LicenseTypeFile,
					PkgName:  "alpine-baselayout",
					FilePath: "some-path",
					Findings: ftypes.LicenseFindings{
						{
							Category:   ftypes.CategoryRestricted,
							Name:       "GPL-2.0",
							Confidence: 1,
							Link:       "https://some-link",
						},
					},
					Layer: ftypes.Layer{
						Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
						DiffID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ConvertFromRPCLicenseFiles(tt.licenseFiles))
		})
	}
}
