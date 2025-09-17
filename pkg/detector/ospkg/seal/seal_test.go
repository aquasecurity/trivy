package seal_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/seal"
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
		baseOS   ftypes.OSType
		fixtures []string
		args     args
		want     []types.DetectedVulnerability
		wantErr  string
	}{
		{
			name:   "Debian scanner",
			baseOS: ftypes.Debian,
			fixtures: []string{
				"testdata/fixtures/seal.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "12",
				pkgs: []ftypes.Package{
					{
						Name:       "seal-wget",
						Version:    "1.21",
						Release:    "1+deb11u1",
						SrcName:    "seal-wget",
						SrcVersion: "1.21",
						SrcRelease: "1+deb11u1",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "seal-wget",
					VulnerabilityID:  "CVE-2024-10524",
					InstalledVersion: "1.21-1+deb11u1",
					FixedVersion:     "1.21-1+deb11u1+sp999",
					DataSource: &dbTypes.DataSource{
						ID:     "seal",
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
						BaseID: "debian",
					},
				},
			},
		},
		{
			name:   "Ubuntu scanner",
			baseOS: ftypes.Ubuntu,
			fixtures: []string{
				"testdata/fixtures/seal.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "22.04",
				pkgs: []ftypes.Package{
					{
						Name:       "seal-wget",
						Version:    "1.21",
						Release:    "1+deb11u1",
						SrcName:    "seal-wget",
						SrcVersion: "1.21",
						SrcRelease: "1+deb11u1",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "seal-wget",
					VulnerabilityID:  "CVE-2024-10524",
					InstalledVersion: "1.21-1+deb11u1",
					FixedVersion:     "1.21-1+deb11u1+sp999",
					DataSource: &dbTypes.DataSource{
						ID:     "seal",
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
						BaseID: "debian",
					},
				},
			},
		},
		{
			name:   "Alpine scanner",
			baseOS: ftypes.Alpine,
			fixtures: []string{
				"testdata/fixtures/seal.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "3.21.5",
				pkgs: []ftypes.Package{
					{
						Name:       "seal-zlib",
						Version:    "1.2.8-r2",
						SrcName:    "seal-zlib",
						SrcVersion: "1.2.8-r2",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "seal-zlib",
					VulnerabilityID:  "CVE-2023-6992",
					InstalledVersion: "1.2.8-r2",
					FixedVersion:     "1.2.8-r25341999",
					DataSource: &dbTypes.DataSource{
						ID:     "seal",
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
						BaseID: "alpine",
					},
				},
			},
		},
		{
			name:   "RedHat scanner",
			baseOS: ftypes.RedHat,
			fixtures: []string{
				"testdata/fixtures/seal.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "9.3",
				pkgs: []ftypes.Package{
					{
						Name:       "seal-wget",
						Version:    "1.12",
						Release:    "10.el6",
						SrcName:    "seal-wget",
						SrcVersion: "1.12",
						SrcRelease: "10.el6",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "seal-wget",
					VulnerabilityID:  "CVE-2024-10524",
					InstalledVersion: "1.12-10.el6",
					FixedVersion:     "1.12-10.el6+sp999",
					DataSource: &dbTypes.DataSource{
						ID:     "seal",
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
						BaseID: "redhat",
					},
				},
			},
		},
		{
			name:   "CentOS scanner",
			baseOS: ftypes.CentOS,
			fixtures: []string{
				"testdata/fixtures/seal.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "8.9",
				pkgs: []ftypes.Package{
					{
						Name:       "seal-wget",
						Version:    "1.12",
						Release:    "10.el6",
						SrcName:    "seal-wget",
						SrcVersion: "1.12",
						SrcRelease: "10.el6",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "seal-wget",
					VulnerabilityID:  "CVE-2024-10524",
					InstalledVersion: "1.12-10.el6",
					FixedVersion:     "1.12-10.el6+sp999",
					DataSource: &dbTypes.DataSource{
						ID:     "seal",
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
						BaseID: "redhat",
					},
				},
			},
		},
		{
			name:   "Get returns an error",
			baseOS: ftypes.Alpine,
			fixtures: []string{
				"testdata/fixtures/invalid.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "3.20",
				pkgs: []ftypes.Package{
					{
						Name:       "seal-jq",
						Version:    "1.5-12",
						SrcName:    "seal-jq",
						SrcVersion: "1.5-12",
					},
				},
			},
			wantErr: "failed to get Seal advisories",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer dbtest.Close()

			scanner := seal.NewScanner(tt.baseOS)
			got, err := scanner.Detect(t.Context(), tt.args.osVer, nil, tt.args.pkgs)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
