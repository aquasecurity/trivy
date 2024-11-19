package suse_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/suse"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Detect(t *testing.T) {
	type args struct {
		osVer string
		pkgs  []ftypes.Package
	}
	tests := []struct {
		name         string
		args         args
		fixtures     []string
		distribution suse.Type
		want         []types.DetectedVulnerability
		wantErr      string
	}{
		{
			name: "happy path",
			fixtures: []string{
				"testdata/fixtures/suse.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			distribution: suse.OpenSUSE,
			args: args{
				osVer: "15.3",
				pkgs: []ftypes.Package{
					{
						Name:       "postgresql",
						Version:    "13",
						Release:    "4.6.6",
						SrcName:    "postgresql",
						SrcVersion: "13",
						SrcRelease: "4.6.6",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "postgresql",
					VulnerabilityID:  "SUSE-SU-2021:0175-1",
					InstalledVersion: "13-4.6.6",
					FixedVersion:     "13-4.6.7",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.SuseCVRF,
						Name: "SUSE CVRF",
						URL:  "https://ftp.suse.com/pub/projects/security/cvrf/",
					},
				},
			},
		},
		{
			name: "happy path: tumbleweed",
			fixtures: []string{
				"testdata/fixtures/tumbleweed.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			distribution: suse.OpenSUSETumbleweed,
			args: args{
				osVer: "",
				pkgs: []ftypes.Package{
					{
						Name:       "singularity-ce",
						Version:    "4.1.3",
						Release:    "1.0",
						SrcName:    "postgresql",
						SrcVersion: "4.1.3",
						SrcRelease: "1.1",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "singularity-ce",
					VulnerabilityID:  "openSUSE-SU-2024:14059-1",
					InstalledVersion: "4.1.3-1.0",
					FixedVersion:     "4.1.3-1.1",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.SuseCVRF,
						Name: "SUSE CVRF",
						URL:  "https://ftp.suse.com/pub/projects/security/cvrf/",
					},
				},
			},
		},
		{
			name: "happy path: suse sle 15sp3",
			fixtures: []string{
				"testdata/fixtures/suse.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			distribution: suse.SUSEEnterpriseLinux,
			args: args{
				osVer: "15.3",
				pkgs: []ftypes.Package{
					{
						Name:       "libopenssl1_1",
						Version:    "1.1.1d",
						Release:    "150200.11.47.1",
						SrcName:    "libopenssl1_1",
						SrcVersion: "1.1.1d",
						SrcRelease: "150200.11.47.1",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "libopenssl1_1",
					VulnerabilityID:  "SUSE-SU-2022:2251-1",
					InstalledVersion: "1.1.1d-150200.11.47.1",
					FixedVersion:     "1.1.1d-150200.11.48.1",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.SuseCVRF,
						Name: "SUSE CVRF",
						URL:  "https://ftp.suse.com/pub/projects/security/cvrf/",
					},
				},
			},
		},
		{
			name: "happy path: suse sle micro 15.3",
			fixtures: []string{
				"testdata/fixtures/suse.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			distribution: suse.SUSEEnterpriseLinuxMicro,
			args: args{
				osVer: "5.3",
				pkgs: []ftypes.Package{
					{
						Name:       "libopenssl1_1",
						Version:    "1.1.1l",
						Release:    "150400.7.21.1",
						SrcName:    "libopenssl1_1",
						SrcVersion: "1.1.1l",
						SrcRelease: "150400.7.21.1",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "libopenssl1_1",
					VulnerabilityID:  "SUSE-SU-2023:0311-1",
					InstalledVersion: "1.1.1l-150400.7.21.1",
					FixedVersion:     "1.1.1l-150400.7.22.1",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.SuseCVRF,
						Name: "SUSE CVRF",
						URL:  "https://ftp.suse.com/pub/projects/security/cvrf/",
					},
				},
			},
		},
		{
			name: "broken bucket",
			fixtures: []string{
				"testdata/fixtures/invalid.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			distribution: suse.SUSEEnterpriseLinux,
			args: args{
				osVer: "15.3",
				pkgs: []ftypes.Package{
					{
						Name:       "jq",
						Version:    "1.6-r0",
						SrcName:    "jq",
						SrcVersion: "1.6-r0",
					},
				},
			},
			wantErr: "failed to get SUSE advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := suse.NewScanner(tt.distribution)
			got, err := s.Detect(nil, tt.args.osVer, nil, tt.args.pkgs)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestScanner_IsSupportedVersion(t *testing.T) {
	type args struct {
		osFamily ftypes.OSType
		osVer    string
	}
	tests := []struct {
		name         string
		now          time.Time
		distribution suse.Type
		args         args
		want         bool
	}{
		{
			name: "opensuse-tumbleweed",
			now:  time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "opensuse-tumbleweed",
				osVer:    "",
			},
			distribution: suse.OpenSUSETumbleweed,
			want:         true,
		},
		{
			name: "opensuse-leap42.3",
			now:  time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "opensuse-leap",
				osVer:    "42.3",
			},
			distribution: suse.OpenSUSE,
			want:         true,
		},
		{
			name: "sles12.3",
			now:  time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "sles",
				osVer:    "12.3",
			},
			distribution: suse.SUSEEnterpriseLinux,
			want:         false,
		},
		{
			name: "latest",
			now:  time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "opensuse-leap",
				osVer:    "999.0",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := clock.With(context.Background(), tt.now)
			s := suse.NewScanner(tt.distribution)
			got := s.IsSupportedVersion(ctx, tt.args.osFamily, tt.args.osVer)
			assert.Equal(t, tt.want, got)
		})
	}
}
