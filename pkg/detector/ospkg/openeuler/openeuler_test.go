package openeuler_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/openeuler"
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
				"testdata/fixtures/openeuler.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "22.03-LTS-SP2",
				pkgs: []ftypes.Package{
					{
						Name:       "perf",
						Version:    "5.10.0",
						Arch:       "x86_64",
						Release:    "153.48.0.125",
						SrcName:    "postgresql",
						SrcVersion: "5.10.0",
						SrcRelease: "153.48.0.125",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "perf",
					VulnerabilityID:  "openEuler-SA-2024-1349",
					InstalledVersion: "5.10.0-153.48.0.125",
					FixedVersion:     "5.10.0-153.48.0.126",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.OpenEuler,
						Name: "openEuler CVRF",
						URL:  "https://repo.openeuler.org/security/data/cvrf",
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
				osVer: "22.03-LTS-SP2",
				pkgs: []ftypes.Package{
					{
						Name:       "perf",
						Version:    "1.6-r0",
						SrcName:    "perf",
						SrcVersion: "1.6-r0",
					},
				},
			},
			wantErr: "failed to get openEuler advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := openeuler.NewScanner()
			got, err := s.Detect(t.Context(), tt.args.osVer, nil, tt.args.pkgs)
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
		name string
		now  time.Time
		args args
		want bool
	}{
		{
			name: "openEuler-20.03-LTS",
			now:  time.Date(2021, 5, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "openEuler",
				osVer:    "20.03-LTS",
			},
			want: true,
		},
		{
			name: "21.09",
			now:  time.Date(2022, 5, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "openEuler",
				osVer:    "21.09",
			},
			want: false,
		},
		{
			name: "22.03-LTS-SP3",
			now:  time.Date(2023, 5, 2, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "openEuler",
				osVer:    "22.03-LTS-SP3",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := clock.With(t.Context(), tt.now)
			s := openeuler.NewScanner()
			got := s.IsSupportedVersion(ctx, tt.args.osFamily, tt.args.osVer)
			assert.Equal(t, tt.want, got)
		})
	}
}
