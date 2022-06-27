package mariner_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/mariner"
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
			name: "happy path 1.0 SrcName and Name are different",
			fixtures: []string{
				"testdata/fixtures/mariner.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "1.0",
				pkgs: []ftypes.Package{
					{
						Name:       "bind-utils",
						Epoch:      0,
						Version:    "9.16.14",
						Release:    "1.cm1",
						Arch:       "aarch64",
						SrcName:    "bind",
						SrcEpoch:   0,
						SrcVersion: "9.16.14",
						SrcRelease: "1.cm1",
						Licenses:   []string{"ISC"},
						Layer:      ftypes.Layer{},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "bind-utils",
					VulnerabilityID:  "CVE-2019-6470",
					InstalledVersion: "9.16.14-1.cm1",
					FixedVersion:     "9.16.15-1.cm1",
					Layer:            ftypes.Layer{},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.CBLMariner,
						Name: "CBL-Mariner Vulnerability Data",
						URL:  "https://github.com/microsoft/CBL-MarinerVulnerabilityData",
					},
				},
			},
		},
		{
			name: "happy path 2.0",
			fixtures: []string{
				"testdata/fixtures/mariner.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "2.0",
				pkgs: []ftypes.Package{
					{
						Name:       "vim",
						Epoch:      0,
						Version:    "8.2.4081",
						Release:    "1.cm1",
						Arch:       "aarch64",
						SrcName:    "vim",
						SrcEpoch:   0,
						SrcVersion: "8.2.4081",
						SrcRelease: "1.cm1",
						Licenses:   []string{"Vim"},
						Layer:      ftypes.Layer{},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "vim",
					VulnerabilityID:  "CVE-2022-0261",
					InstalledVersion: "8.2.4081-1.cm1",
					Layer:            ftypes.Layer{},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.CBLMariner,
						Name: "CBL-Mariner Vulnerability Data",
						URL:  "https://github.com/microsoft/CBL-MarinerVulnerabilityData",
					},
				},
			},
		},
		{
			name:     "broken advisory",
			fixtures: []string{"testdata/fixtures/invalid.yaml", "testdata/fixtures/data-source.yaml"},
			args: args{
				osVer: "1.0",
				pkgs: []ftypes.Package{
					{
						Name:       "bind-utils",
						Epoch:      0,
						Version:    "9.16.14",
						Release:    "1.cm1",
						Arch:       "aarch64",
						SrcName:    "bind",
						SrcEpoch:   0,
						SrcVersion: "9.16.14",
						SrcRelease: "1.cm1",
						Licenses:   []string{"ISC"},
						Layer:      ftypes.Layer{},
					},
				},
			},
			wantErr: "failed to get CBL-Mariner advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := mariner.NewScanner()
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
