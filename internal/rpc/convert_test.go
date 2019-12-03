package rpc

import (
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/log"

	"github.com/aquasecurity/fanal/analyzer"
	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/rpc/detector"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	log.InitLogger(false, false)
	code := m.Run()
	os.Exit(code)
}

func TestConvertToRpcPkgs(t *testing.T) {
	type args struct {
		pkgs []analyzer.Package
	}
	tests := []struct {
		name string
		args args
		want []*detector.Package
	}{
		{
			name: "happy path",
			args: args{
				pkgs: []analyzer.Package{
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
			want: []*detector.Package{
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
		rpcPkgs []*detector.Package
	}
	tests := []struct {
		name string
		args args
		want []analyzer.Package
	}{
		{
			args: args{
				rpcPkgs: []*detector.Package{
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
			want: []analyzer.Package{
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
		rpcLibs []*detector.Library
	}
	tests := []struct {
		name string
		args args
		want []ptypes.Library
	}{
		{
			name: "happy path",
			args: args{
				rpcLibs: []*detector.Library{
					{Name: "foo", Version: "1.2.3"},
					{Name: "bar", Version: "4.5.6"},
				},
			},
			want: []ptypes.Library{
				{Name: "foo", Version: "1.2.3"},
				{Name: "bar", Version: "4.5.6"},
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
		want []*detector.Library
	}{
		{
			name: "happy path",
			args: args{
				libs: []ptypes.Library{
					{Name: "foo", Version: "1.2.3"},
					{Name: "bar", Version: "4.5.6"},
				},
			},
			want: []*detector.Library{
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
		rpcVulns []*detector.Vulnerability
	}
	tests := []struct {
		name string
		args args
		want []types.DetectedVulnerability
	}{
		{
			name: "happy path",
			args: args{
				rpcVulns: []*detector.Vulnerability{
					{
						VulnerabilityId:  "CVE-2019-0001",
						PkgName:          "foo",
						InstalledVersion: "1.2.3",
						FixedVersion:     "1.2.4",
						Title:            "DoS",
						Description:      "Denial of Service",
						Severity:         detector.Severity_CRITICAL,
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
		want []*detector.Vulnerability
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
							References:  []string{"http://example.com"},
						},
					},
				},
			},
			want: []*detector.Vulnerability{
				{
					VulnerabilityId:  "CVE-2019-0001",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "1.2.4",
					Title:            "DoS",
					Description:      "Denial of Service",
					Severity:         detector.Severity_MEDIUM,
					References:       []string{"http://example.com"},
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
					},
				},
			},
			want: []*detector.Vulnerability{
				{
					VulnerabilityId:  "CVE-2019-0002",
					PkgName:          "bar",
					InstalledVersion: "1.2.3",
					FixedVersion:     "1.2.4",
					Title:            "DoS",
					Description:      "Denial of Service",
					Severity:         detector.Severity_UNKNOWN,
					References:       []string{"http://example.com"},
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
