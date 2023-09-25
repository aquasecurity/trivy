package photon_test

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
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/photon"
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
				"testdata/fixtures/photon.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "1.0",
				pkgs: []ftypes.Package{
					{
						Name:       "PyYAML",
						Version:    "3.12",
						Release:    "4.ph1",
						SrcName:    "PyYAML",
						SrcVersion: "3.12",
						SrcRelease: "4.ph1",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "PyYAML",
					VulnerabilityID:  "CVE-2020-1747",
					InstalledVersion: "3.12-4.ph1",
					FixedVersion:     "3.12-5.ph1",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Photon,
						Name: "Photon OS CVE metadata",
						URL:  "https://packages.vmware.com/photon/photon_cve_metadata/",
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
				osVer: "1.0",
				pkgs: []ftypes.Package{
					{
						Name:       "PyYAML",
						Version:    "3.12",
						SrcName:    "PyYAML",
						SrcVersion: "3.12",
					},
				},
			},
			wantErr: "failed to get Photon advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := photon.NewScanner()
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
		name string
		now  time.Time
		args args
		want bool
	}{
		{
			name: "photon 1.0",
			now:  time.Date(2022, 1, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "photon",
				osVer:    "1.0",
			},
			want: true,
		},
		{
			name: "photon 1.0 EOL",
			now:  time.Date(2022, 3, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "photon",
				osVer:    "1.0",
			},
			want: false,
		},
		{
			name: "unknown",
			now:  time.Date(2022, 1, 31, 23, 59, 59, 0, time.UTC),
			args: args{
				osFamily: "photon",
				osVer:    "unknown",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := photon.NewScanner(photon.WithClock(fake.NewFakeClock(tt.now)))
			got := s.IsSupportedVersion(tt.args.osFamily, tt.args.osVer)
			assert.Equal(t, tt.want, got)
		})
	}
}
