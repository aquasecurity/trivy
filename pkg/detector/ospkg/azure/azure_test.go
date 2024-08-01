package azure_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	azurevs "github.com/aquasecurity/trivy-db/pkg/vulnsrc/azure"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/azure"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Detect(t *testing.T) {
	type args struct {
		dist  azurevs.Distribution
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
				"testdata/fixtures/azure.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				dist:  azurevs.Mariner,
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
				"testdata/fixtures/azure.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				dist:  azurevs.Mariner,
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
			name: "happy path 3.0",
			fixtures: []string{
				"testdata/fixtures/azure.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				dist:  azurevs.Azure,
				osVer: "3.0",
				pkgs: []ftypes.Package{
					{
						Name:       "php",
						Epoch:      0,
						Version:    "8.3.6",
						Release:    "1.azl3",
						Arch:       "aarch64",
						SrcName:    "php",
						SrcEpoch:   0,
						SrcVersion: "8.3.6",
						SrcRelease: "1.azl3",
						Licenses:   []string{"Php"},
						Layer:      ftypes.Layer{},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "php",
					VulnerabilityID:  "CVE-2024-2408",
					InstalledVersion: "8.3.6-1.azl3",
					FixedVersion:     "8.3.8-1.azl3",
					Layer:            ftypes.Layer{},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.AzureLinux,
						Name: "Azure Linux Vulnerability Data",
						URL:  "https://github.com/microsoft/AzureLinuxVulnerabilityData",
					},
				},
			},
		},
		{
			name: "broken advisory",
			fixtures: []string{
				"testdata/fixtures/invalid.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				dist:  azurevs.Mariner,
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
			wantErr: "failed to get Azure Linux advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := azure.NewAzureScanner()
			if tt.args.dist == azurevs.Mariner {
				s = azure.NewMarinerScanner()
			}
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
