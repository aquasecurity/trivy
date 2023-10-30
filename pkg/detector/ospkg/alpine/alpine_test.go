package alpine_test

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fake "k8s.io/utils/clock/testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/alpine"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Detect(t *testing.T) {
	type args struct {
		osVer string
		repo  *ftypes.Repository
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
				"testdata/fixtures/alpine.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "3.10.2",
				pkgs: []ftypes.Package{
					{
						Name:       "ansible",
						Version:    "2.6.4",
						SrcName:    "ansible",
						SrcVersion: "2.6.4",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
					{
						Name:       "invalid",
						Version:    "invalid", // skipped
						SrcName:    "invalid",
						SrcVersion: "invalid",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "ansible",
					VulnerabilityID:  "CVE-2019-10217",
					InstalledVersion: "2.6.4",
					FixedVersion:     "2.8.4-r0",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Alpine,
						Name: "Alpine Secdb",
						URL:  "https://secdb.alpinelinux.org/",
					},
				},
				{
					PkgName:          "ansible",
					VulnerabilityID:  "CVE-2021-20191",
					InstalledVersion: "2.6.4",
					FixedVersion:     "",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Alpine,
						Name: "Alpine Secdb",
						URL:  "https://secdb.alpinelinux.org/",
					},
				},
			},
		},
		{
			name: "contain rc",
			fixtures: []string{
				"testdata/fixtures/alpine.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "3.10",
				pkgs: []ftypes.Package{
					{
						Name:       "jq",
						Version:    "1.6-r0",
						SrcName:    "jq",
						SrcVersion: "1.6-r0",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "jq",
					VulnerabilityID:  "CVE-2020-1234",
					InstalledVersion: "1.6-r0",
					FixedVersion:     "1.6-r1",
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Alpine,
						Name: "Alpine Secdb",
						URL:  "https://secdb.alpinelinux.org/",
					},
				},
			},
		},
		{
			name: "contain pre",
			fixtures: []string{
				"testdata/fixtures/alpine.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "3.10",
				pkgs: []ftypes.Package{
					{
						Name:       "test",
						Version:    "0.1.0_alpha",
						SrcName:    "test-src",
						SrcVersion: "0.1.0_alpha",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2030-0002",
					PkgName:          "test",
					InstalledVersion: "0.1.0_alpha",
					FixedVersion:     "0.1.0_alpha2",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Alpine,
						Name: "Alpine Secdb",
						URL:  "https://secdb.alpinelinux.org/",
					},
				},
			},
		},
		{
			name: "repository is newer than OS version",
			fixtures: []string{
				"testdata/fixtures/alpine.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "3.9.3",
				repo: &ftypes.Repository{
					Family:  ftypes.Alpine,
					Release: "3.10",
				},
				pkgs: []ftypes.Package{
					{
						Name:       "jq",
						Version:    "1.6-r0",
						SrcName:    "jq",
						SrcVersion: "1.6-r0",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "jq",
					VulnerabilityID:  "CVE-2020-1234",
					InstalledVersion: "1.6-r0",
					FixedVersion:     "1.6-r1",
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Alpine,
						Name: "Alpine Secdb",
						URL:  "https://secdb.alpinelinux.org/",
					},
				},
			},
		},
		{
			name: "Get returns an error",
			fixtures: []string{
				"testdata/fixtures/invalid.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "3.10.2",
				pkgs: []ftypes.Package{
					{
						Name:       "jq",
						Version:    "1.6-r0",
						SrcName:    "jq",
						SrcVersion: "1.6-r0",
					},
				},
			},
			wantErr: "failed to get alpine advisories",
		},
		{
			name: "No src name",
			fixtures: []string{
				"testdata/fixtures/alpine.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "3.9.3",
				repo: &ftypes.Repository{
					Family:  ftypes.Alpine,
					Release: "3.10",
				},
				pkgs: []ftypes.Package{
					{
						Name:       "jq",
						Version:    "1.6-r0",
						SrcVersion: "1.6-r0",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "jq",
					VulnerabilityID:  "CVE-2020-1234",
					InstalledVersion: "1.6-r0",
					FixedVersion:     "1.6-r1",
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Alpine,
						Name: "Alpine Secdb",
						URL:  "https://secdb.alpinelinux.org/",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := alpine.NewScanner()
			got, err := s.Detect(tt.args.osVer, tt.args.repo, tt.args.pkgs)
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
			name: "alpine 3.6",
			now:  time.Date(2019, 3, 2, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "alpine",
				osVer:    "3.6",
			},
			want: true,
		},
		{
			name: "alpine 3.6 with EOL",
			now:  time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "alpine",
				osVer:    "3.6.5",
			},
			want: false,
		},
		{
			name: "alpine 3.9",
			now:  time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "alpine",
				osVer:    "3.9.0",
			},
			want: true,
		},
		{
			name: "alpine 3.10",
			now:  time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "alpine",
				osVer:    "3.10",
			},
			want: true,
		},
		{
			name: "unknown",
			now:  time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "alpine",
				osVer:    "unknown",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := alpine.NewScanner(alpine.WithClock(fake.NewFakeClock(tt.now)))
			got := s.IsSupportedVersion(tt.args.osFamily, tt.args.osVer)
			assert.Equal(t, tt.want, got)
		})
	}
}
