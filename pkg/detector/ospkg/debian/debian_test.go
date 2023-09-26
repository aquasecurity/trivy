package debian_test

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
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/debian"
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
				"testdata/fixtures/debian.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "9.1",
				pkgs: []ftypes.Package{
					{
						Name:       "htpasswd",
						Version:    "2.4.24",
						SrcName:    "apache2",
						SrcVersion: "2.4.24",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "htpasswd",
					VulnerabilityID:  "CVE-2020-11985",
					VendorIDs:        []string{"DSA-4884-1"},
					InstalledVersion: "2.4.24",
					FixedVersion:     "2.4.25-1",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Debian,
						Name: "Debian Security Tracker",
						URL:  "https://salsa.debian.org/security-tracker-team/security-tracker",
					},
				},
				{
					PkgName:          "htpasswd",
					VulnerabilityID:  "CVE-2021-31618",
					InstalledVersion: "2.4.24",
					Status:           dbTypes.StatusWillNotFix,
					SeveritySource:   vulnerability.Debian,
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityMedium.String(),
					},
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Debian,
						Name: "Debian Security Tracker",
						URL:  "https://salsa.debian.org/security-tracker-team/security-tracker",
					},
				},
			},
		},
		{
			name: "invalid bucket",
			fixtures: []string{
				"testdata/fixtures/invalid.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "9.1",
				pkgs: []ftypes.Package{
					{
						Name:       "htpasswd",
						Version:    "2.4.24",
						SrcName:    "apache2",
						SrcVersion: "2.4.24",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			wantErr: "failed to unmarshal advisory JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := debian.NewScanner()
			got, err := s.Detect(tt.args.osVer, nil, tt.args.pkgs)
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
			name: "debian 7",
			now:  time.Date(2018, 3, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "debian",
				osVer:    "7",
			},
			want: true,
		},
		{
			name: "debian 8 EOL",
			now:  time.Date(2020, 7, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "debian",
				osVer:    "8.2",
			},
			want: false,
		},
		{
			name: "unknown",
			now:  time.Date(2020, 7, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "debian",
				osVer:    "unknown",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := debian.NewScanner(debian.WithClock(fake.NewFakeClock(tt.now)))
			got := s.IsSupportedVersion(tt.args.osFamily, tt.args.osVer)
			assert.Equal(t, tt.want, got)
		})
	}
}
