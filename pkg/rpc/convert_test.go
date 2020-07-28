package rpc

import (
	"os"
	"testing"

	"github.com/aquasecurity/trivy/rpc/common"

	ftypes "github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/trivy/pkg/log"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	log.InitLogger(false, false)
	code := m.Run()
	os.Exit(code)
}

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
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertToRpcPkgs(tt.args.pkgs)
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
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertFromRpcPkgs(tt.args.rpcPkgs)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}

func TestConvertFromRpcLibraries(t *testing.T) {
	type args struct {
		rpcLibs []*common.Library
	}
	tests := []struct {
		name string
		args args
		want []ftypes.LibraryInfo
	}{
		{
			name: "happy path",
			args: args{
				rpcLibs: []*common.Library{
					{Name: "foo", Version: "1.2.3"},
					{Name: "bar", Version: "4.5.6"},
				},
			},
			want: []ftypes.LibraryInfo{
				{Library: ptypes.Library{Name: "foo", Version: "1.2.3"}},
				{Library: ptypes.Library{Name: "bar", Version: "4.5.6"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertFromRpcLibraries(tt.args.rpcLibs)
			assert.Equal(t, got, tt.want, tt.name)
		})
	}
}

func TestConvertToRpcLibraries(t *testing.T) {
	type args struct {
		libs []ptypes.Library
	}
	tests := []struct {
		name string
		args args
		want []*common.Library
	}{
		{
			name: "happy path",
			args: args{
				libs: []ptypes.Library{
					{Name: "foo", Version: "1.2.3"},
					{Name: "bar", Version: "4.5.6"},
				},
			},
			want: []*common.Library{
				{Name: "foo", Version: "1.2.3"},
				{Name: "bar", Version: "4.5.6"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertToRpcLibraries(tt.args.libs)
			assert.Equal(t, got, tt.want, tt.name)
		})
	}
}

func TestConvertFromRpcVulns(t *testing.T) {
	type args struct {
		rpcVulns []*common.Vulnerability
	}
	tests := []struct {
		name string
		args args
		want []types.DetectedVulnerability
	}{
		{
			name: "happy path",
			args: args{
				rpcVulns: []*common.Vulnerability{
					{
						VulnerabilityId:  "CVE-2019-0001",
						PkgName:          "foo",
						InstalledVersion: "1.2.3",
						FixedVersion:     "1.2.4",
						Title:            "DoS",
						Description:      "Denial of Service",
						Severity:         common.Severity_CRITICAL,
						References:       []string{"http://example.com"},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2019-0001",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "1.2.4",
					Vulnerability: dbTypes.Vulnerability{
						Title:       "DoS",
						Description: "Denial of Service",
						Severity:    "CRITICAL",
						References:  []string{"http://example.com"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertFromRpcVulns(tt.args.rpcVulns)
			assert.Equal(t, got, tt.want, tt.name)
		})
	}
}

func TestConvertToRpcVulns(t *testing.T) {
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
							CVSS: dbTypes.VendorCVSS{
								"redhat": {
									V2Vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C",
									V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
									V2Score:  7.2,
									V3Score:  7.8,
								},
							},
							References: []string{"http://example.com"},
						},
						Layer: ftypes.Layer{
							Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
							DiffID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
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
					Cvss:             make(map[string]*common.CVSS),
					References:       []string{"http://example.com"},
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
			got := ConvertToRpcVulns(tt.args.vulns)
			assert.Equal(t, got, tt.want, tt.name)
		})
	}
}
