package redhat_test

import (
	"sort"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/redhat"

	fake "k8s.io/utils/clock/testing"

	ftypes "github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		wantErr  string
	}{
		{
			name:     "happy path: src pkg name is different from bin pkg name",
			fixtures: []string{"testdata/fixtures/redhat.yaml"},
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
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2017-5953",
					PkgName:          "vim-minimal",
					InstalledVersion: "2:7.4.160-5.el7",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
				{
					VulnerabilityID:  "CVE-2017-6350",
					PkgName:          "vim-minimal",
					InstalledVersion: "2:7.4.160-5.el7",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
				{
					VulnerabilityID:  "CVE-2019-12735",
					PkgName:          "vim-minimal",
					InstalledVersion: "2:7.4.160-5.el7",
					FixedVersion:     "2:7.4.160-6.el7_6",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
			},
		},
		{
			name:     "happy path: src pkg name is the same as bin pkg name",
			fixtures: []string{"testdata/fixtures/redhat.yaml"},
			args: args{
				osVer: "7.3",
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
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2015-2808",
					PkgName:          "nss",
					InstalledVersion: "3.36.0-7.1.el7_6",
				},
				{
					VulnerabilityID:  "CVE-2016-2183",
					PkgName:          "nss",
					InstalledVersion: "3.36.0-7.1.el7_6",
				},
				{
					VulnerabilityID:  "CVE-2018-12404",
					PkgName:          "nss",
					InstalledVersion: "3.36.0-7.1.el7_6",
					FixedVersion:     "3.44.0-4.el7",
				},
			},
		},
		{
			name:     "happy path: modular packages",
			fixtures: []string{"testdata/fixtures/redhat.yaml"},
			args: args{
				osVer: "8.3",
				pkgs: []ftypes.Package{
					{
						Name:            "php",
						Version:         "7.2.24",
						Release:         "1.module_el8.2.0+313+b04d0a66",
						Arch:            "x86_64",
						Epoch:           0,
						SrcName:         "php",
						SrcVersion:      "7.2.24",
						SrcRelease:      "1.module_el8.2.0+313+b04d0a66",
						SrcEpoch:        0,
						Modularitylabel: "php:7.2:8020020200507003613:2c7ca891",
						Layer: ftypes.Layer{
							DiffID: "sha256:3e968ecc016e1b9aa19023798229bf2d25c813d1bf092533f38b056aff820524",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2019-11043",
					PkgName:          "php",
					InstalledVersion: "7.2.24-1.module_el8.2.0+313+b04d0a66",
					FixedVersion:     "7.3.5-5.module+el8.1.0+4560+e0eee7d6",
					Layer: ftypes.Layer{
						DiffID: "sha256:3e968ecc016e1b9aa19023798229bf2d25c813d1bf092533f38b056aff820524",
					},
				},
			},
		},
		{
			name:     "happy path: packages from remi repository are skipped",
			fixtures: []string{"testdata/fixtures/redhat.yaml"},
			args: args{
				osVer: "7.6",
				pkgs: []ftypes.Package{
					{
						Name:       "php",
						Version:    "7.3.23",
						Release:    "1.el7.remi",
						Arch:       "x86_64",
						Epoch:      0,
						SrcName:    "php",
						SrcVersion: "7.3.23",
						SrcRelease: "1.el7.remi",
						SrcEpoch:   0,
						Layer: ftypes.Layer{
							DiffID: "sha256:c27b3cf4d516baf5932d5df3a573c6a571ddace3ee2a577492292d2e849c112b",
						},
					},
				},
			},
			want: []types.DetectedVulnerability(nil),
		},
		{
			name:     "invalid bucket",
			fixtures: []string{"testdata/fixtures/invalid.yaml"},
			args: args{
				osVer: "6",
				pkgs: []ftypes.Package{
					{
						Name:       "jq",
						Version:    "3.36.0",
						SrcName:    "jq",
						SrcVersion: "3.36.0",
					},
				},
			},
			wantErr: "failed to get Red Hat advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := redhat.NewScanner()
			got, err := s.Detect(tt.args.osVer, tt.args.pkgs)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			sort.Slice(got, func(i, j int) bool {
				return got[i].VulnerabilityID < got[j].VulnerabilityID
			})
			assert.NoError(t, err)
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
