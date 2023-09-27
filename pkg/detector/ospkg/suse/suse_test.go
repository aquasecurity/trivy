package suse_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fake "k8s.io/utils/clock/testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/dbtest"
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
			got, err := s.Detect(tt.args.osVer, nil, tt.args.pkgs)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
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
		name         string
		now          time.Time
		distribution suse.Type
		args         args
		want         bool
	}{
		{
			name: "opensuse.leap42.3",
			now:  time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "opensuse.leap",
				osVer:    "42.3",
			},
			distribution: suse.OpenSUSE,
			want:         true,
		},
		{
			name: "sles12.3",
			now:  time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "suse linux enterprise server",
				osVer:    "12.3",
			},
			distribution: suse.SUSEEnterpriseLinux,
			want:         false,
		},
		{
			name: "unknown",
			now:  time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "unknown",
				osVer:    "unknown",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := suse.NewScanner(tt.distribution, suse.WithClock(fake.NewFakeClock(tt.now)))
			got := s.IsSupportedVersion(tt.args.osFamily, tt.args.osVer)
			assert.Equal(t, tt.want, got)
		})
	}
}
