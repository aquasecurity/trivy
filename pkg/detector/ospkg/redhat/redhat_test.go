package redhat_test

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	fake "k8s.io/utils/clock/testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/redhat"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestMain(m *testing.M) {
	log.InitLogger(false, false)
	os.Exit(m.Run())
}

func TestScanner_Detect(t *testing.T) {
	type args struct {
		osVer string
		pkgs  []ftypes.Package
	}
	tests := []struct {
		name     string
		fixtures []string
		args     args
		want     []types.DetectedVulnerability
		wantErr  bool
	}{
		{
			name: "happy path",
			fixtures: []string{
				"testdata/fixtures/redhat.yaml",
				"testdata/fixtures/cpe.yaml",
			},
			args: args{
				osVer: "7.6",
				pkgs: []ftypes.Package{
					{
						Name:       "vim-minimal",
						Version:    "7.4.160",
						Release:    "5.el7",
						Epoch:      2,
						Arch:       "x86_64",
						SrcName:    "vim",
						SrcVersion: "7.4.160",
						SrcRelease: "5.el7",
						SrcEpoch:   2,
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
						BuildInfo: &ftypes.BuildInfo{
							ContentSets: []string{"rhel-7-server-rpms"},
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2017-5953",
					PkgName:          "vim-minimal",
					InstalledVersion: "2:7.4.160-5.el7",
					SeveritySource:   vulnerability.RedHat,
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityLow.String(),
					},
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
				{
					VulnerabilityID:  "CVE-2019-12735",
					VendorIDs:        []string{"RHSA-2019:1619"},
					PkgName:          "vim-minimal",
					InstalledVersion: "2:7.4.160-5.el7",
					FixedVersion:     "2:7.4.160-6.el7_6",
					SeveritySource:   vulnerability.RedHat,
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
			},
		},
		{
			name: "happy path: multiple RHSA-IDs",
			fixtures: []string{
				"testdata/fixtures/redhat.yaml",
				"testdata/fixtures/cpe.yaml",
			},
			args: args{
				osVer: "7.5",
				pkgs: []ftypes.Package{
					{
						Name:       "nss",
						Version:    "3.36.0",
						Release:    "7.1.el7_6",
						Epoch:      0,
						Arch:       "x86_64",
						SrcName:    "nss",
						SrcVersion: "3.36.0",
						SrcRelease: "7.4.160",
						SrcEpoch:   0,
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
						BuildInfo: &ftypes.BuildInfo{
							ContentSets: []string{"rhel-7-server-rpms"},
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2019-17007",
					VendorIDs:        []string{"RHSA-2021:0876"},
					PkgName:          "nss",
					InstalledVersion: "3.36.0-7.1.el7_6",
					FixedVersion:     "3.36.0-9.el7_6",
					SeveritySource:   vulnerability.RedHat,
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityMedium.String(),
					},
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
				{
					VulnerabilityID:  "CVE-2020-12403",
					VendorIDs:        []string{"RHSA-2021:0538", "RHSA-2021:0876"},
					PkgName:          "nss",
					InstalledVersion: "3.36.0-7.1.el7_6",
					FixedVersion:     "3.53.1-17.el7_3",
					SeveritySource:   vulnerability.RedHat,
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
			},
		},
		{
			name: "happy path: package without architecture",
			fixtures: []string{
				"testdata/fixtures/redhat.yaml",
				"testdata/fixtures/cpe.yaml",
			},
			args: args{
				osVer: "7.6",
				pkgs: []ftypes.Package{
					{
						Name:       "kernel-headers",
						Version:    "3.10.0-1127.19",
						Release:    "1.el7",
						Epoch:      0,
						Arch:       "noarch",
						SrcName:    "kernel-headers",
						SrcVersion: "3.10.0-1127.19",
						SrcRelease: "1.el7",
						SrcEpoch:   0,
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
						BuildInfo: &ftypes.BuildInfo{
							ContentSets: []string{"rhel-7-server-rpms"},
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2016-5195",
					VendorIDs:        []string{"RHSA-2017:0372"},
					PkgName:          "kernel-headers",
					InstalledVersion: "3.10.0-1127.19-1.el7",
					FixedVersion:     "4.5.0-15.2.1.el7",
					SeveritySource:   vulnerability.RedHat,
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
			},
		},
		{
			name: "happy path: advisories have different arches",
			fixtures: []string{
				"testdata/fixtures/redhat.yaml",
				"testdata/fixtures/cpe.yaml",
			},
			args: args{
				osVer: "7.6",
				pkgs: []ftypes.Package{
					{
						Name:       "kernel-headers",
						Version:    "3.10.0-326.36",
						Release:    "3.el7",
						Epoch:      0,
						Arch:       "x86_64",
						SrcName:    "kernel-headers",
						SrcVersion: "3.10.0-326.36",
						SrcRelease: "3.el7",
						SrcEpoch:   0,
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
						BuildInfo: &ftypes.BuildInfo{
							ContentSets: []string{"rhel-7-server-rpms"},
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2016-5195",
					VendorIDs:        []string{"RHSA-2016:2098"},
					PkgName:          "kernel-headers",
					InstalledVersion: "3.10.0-326.36-3.el7",
					FixedVersion:     "3.10.0-327.36.3.el7",
					SeveritySource:   vulnerability.RedHat,
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
			},
		},
		{
			name: "no build info",
			fixtures: []string{
				"testdata/fixtures/redhat.yaml",
				"testdata/fixtures/cpe.yaml",
			},
			args: args{
				osVer: "8.3",
				pkgs: []ftypes.Package{
					{
						Name:    "vim-minimal",
						Version: "7.4.160",
						Release: "5.el8",
						Epoch:   2,
						Arch:    "x86_64",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2019-12735",
					VendorIDs:        []string{"RHSA-2019:1619"},
					PkgName:          "vim-minimal",
					InstalledVersion: "2:7.4.160-5.el8",
					FixedVersion:     "2:7.4.160-7.el8_7",
					SeveritySource:   vulnerability.RedHat,
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityMedium.String(),
					},
				},
			},
		},
		{
			name: "modular packages",
			fixtures: []string{
				"testdata/fixtures/redhat.yaml",
				"testdata/fixtures/cpe.yaml",
			},
			args: args{
				osVer: "8.3",
				pkgs: []ftypes.Package{
					{
						Name:            "php",
						Version:         "7.2.10",
						Release:         "1.module_el8.2.0+313+b04d0a66",
						Arch:            "x86_64",
						SrcName:         "php",
						SrcVersion:      "7.2.10",
						SrcRelease:      "1.module_el8.2.0+313+b04d0a66",
						Modularitylabel: "php:7.2:8020020200507003613:2c7ca891",
						Layer: ftypes.Layer{
							DiffID: "sha256:3e968ecc016e1b9aa19023798229bf2d25c813d1bf092533f38b056aff820524",
						},
						BuildInfo: &ftypes.BuildInfo{
							Nvr:  "ubi8-init-container-8.0-7",
							Arch: "x86_64",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2019-11043",
					VendorIDs:        []string{"RHSA-2020:0322"},
					PkgName:          "php",
					InstalledVersion: "7.2.10-1.module_el8.2.0+313+b04d0a66",
					FixedVersion:     "7.2.11-1.1.module+el8.0.0+4664+17bd8d65",
					SeveritySource:   vulnerability.RedHat,
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityCritical.String(),
					},
					Layer: ftypes.Layer{
						DiffID: "sha256:3e968ecc016e1b9aa19023798229bf2d25c813d1bf092533f38b056aff820524",
					},
				},
			},
		},
		{
			name: "packages from remi repository are skipped",
			args: args{
				osVer: "7.6",
				pkgs: []ftypes.Package{
					{
						Name:    "php",
						Version: "7.3.23",
						Release: "1.el7.remi",
						Arch:    "x86_64",
						BuildInfo: &ftypes.BuildInfo{
							ContentSets: []string{"rhel-7-server-rpms"},
						},
					},
				},
			},
			want: []types.DetectedVulnerability(nil),
		},
		{
			name: "broken value",
			fixtures: []string{
				"testdata/fixtures/invalid-type.yaml",
				"testdata/fixtures/cpe.yaml",
			},
			args: args{
				osVer: "7",
				pkgs: []ftypes.Package{
					{
						Name:    "nss",
						Version: "3.36.0",
						Release: "7.1.el7_6",
						Arch:    "x86_64",
						BuildInfo: &ftypes.BuildInfo{
							ContentSets: []string{"rhel-7-server-rpms"},
						},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbtest.InitDB(t, tt.fixtures)
			defer func() { _ = dbtest.Close() }()

			s := redhat.NewScanner()
			got, err := s.Detect(tt.args.osVer, nil, tt.args.pkgs)
			require.Equal(t, tt.wantErr, err != nil, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestScanner_IsSupportedVersion(t *testing.T) {
	type args struct {
		osFamily string
		osVer    string
	}
	tests := []struct {
		name string
		now  time.Time
		args args
		want bool
	}{
		{
			name: "centos 6",
			now:  time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "centos",
				osVer:    "6.8",
			},
			want: true,
		},
		{
			name: "centos 6 EOL",
			now:  time.Date(2020, 12, 1, 0, 0, 0, 0, time.UTC),
			args: args{
				osFamily: "centos",
				osVer:    "6.7",
			},
			want: false,
		},
		{
			name: "two dots",
			now:  time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "centos",
				osVer:    "8.0.1",
			},
			want: true,
		},
		{
			name: "rhel 8",
			now:  time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "redhat",
				osVer:    "8.0",
			},
			want: true,
		},
		{
			name: "unknown",
			now:  time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "unknown",
				osVer:    "8.0",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := redhat.NewScanner(redhat.WithClock(fake.NewFakeClock(tt.now)))
			got := s.IsSupportedVersion(tt.args.osFamily, tt.args.osVer)
			assert.Equal(t, tt.want, got)
		})
	}
}
