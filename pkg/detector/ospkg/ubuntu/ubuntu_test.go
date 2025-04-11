package ubuntu_test

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/ubuntu"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Detect(t *testing.T) {
	type args struct {
		osVer string
		pkgs  []ftypes.Package
	}
	tests := []struct {
		name     string
		args     args
		fixtures []string
		want     []types.DetectedVulnerability
		wantErr  string
	}{
		{
			name: "happy path",
			fixtures: []string{
				"testdata/fixtures/ubuntu.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "20.04",
				pkgs: []ftypes.Package{
					{
						Name:       "wpa",
						Version:    "2.9",
						SrcName:    "wpa",
						SrcVersion: "2.9",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "wpa",
					VulnerabilityID:  "CVE-2019-9243",
					InstalledVersion: "2.9",
					FixedVersion:     "",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Ubuntu,
						Name: "Ubuntu CVE Tracker",
						URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
					},
				},
				{
					PkgName:          "wpa",
					VulnerabilityID:  "CVE-2021-27803",
					InstalledVersion: "2.9",
					FixedVersion:     "2:2.9-1ubuntu4.3",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Ubuntu,
						Name: "Ubuntu CVE Tracker",
						URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
					},
				},
			},
		},
		{
			name: "ubuntu 20.04-ESM. 20.04 is not outdated",
			fixtures: []string{
				"testdata/fixtures/ubuntu.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "20.04-ESM",
				pkgs: []ftypes.Package{
					{
						Name:       "wpa",
						Version:    "2.9",
						SrcName:    "wpa",
						SrcVersion: "2.9",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "wpa",
					VulnerabilityID:  "CVE-2019-9243",
					InstalledVersion: "2.9",
					FixedVersion:     "",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Ubuntu,
						Name: "Ubuntu CVE Tracker",
						URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
					},
				},
				{
					PkgName:          "wpa",
					VulnerabilityID:  "CVE-2021-27803",
					InstalledVersion: "2.9",
					FixedVersion:     "2:2.9-1ubuntu4.3",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Ubuntu,
						Name: "Ubuntu CVE Tracker",
						URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
					},
				},
			},
		},
		{
			name: "ubuntu 19.04-ESM, 19.04 is outdated", // Use 19.04-ESM for testing, although it doesn't exist
			fixtures: []string{
				"testdata/fixtures/ubuntu.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "19.04-ESM",
				pkgs: []ftypes.Package{
					{
						Name:       "wpa",
						Version:    "2.9",
						SrcName:    "wpa",
						SrcVersion: "2.9",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
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
			args: args{
				osVer: "21.04",
				pkgs: []ftypes.Package{
					{
						Name:       "jq",
						Version:    "1.6-r0",
						SrcName:    "jq",
						SrcVersion: "1.6-r0",
					},
				},
			},
			wantErr: "failed to get Ubuntu advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := ubuntu.NewScanner()
			got, err := s.Detect(nil, tt.args.osVer, nil, tt.args.pkgs)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			sort.Slice(got, func(i, j int) bool {
				return got[i].VulnerabilityID < got[j].VulnerabilityID
			})
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
		name string
		now  time.Time
		args args
		want bool
	}{
		{
			name: "ubuntu 12.04 eol ends",
			now:  time.Date(2019, 3, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "ubuntu",
				osVer:    "12.04",
			},
			want: true,
		},
		{
			name: "ubuntu12.04",
			now:  time.Date(2019, 4, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "ubuntu",
				osVer:    "12.04",
			},
			want: false,
		},
		{
			name: "ubuntu 18.04 ESM. 18.04 is not outdated",
			now:  time.Date(2022, 4, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "ubuntu",
				osVer:    "18.04-ESM",
			},
			want: true,
		},
		{
			name: "ubuntu 18.04 ESM. 18.04 is outdated",
			now:  time.Date(2030, 4, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "ubuntu",
				osVer:    "18.04-ESM",
			},
			want: false,
		},
		{
			name: "latest",
			now:  time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "ubuntu",
				osVer:    "99.04",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := clock.With(t.Context(), tt.now)
			s := ubuntu.NewScanner()
			got := s.IsSupportedVersion(ctx, tt.args.osFamily, tt.args.osVer)
			assert.Equal(t, tt.want, got)
		})
	}
}
