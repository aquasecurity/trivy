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
			name:   "non-Seal package is scanned with the base OS scanner",
			baseOS: ftypes.Debian,
			fixtures: []string{
				"testdata/fixtures/seal.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "12",
				pkgs: []ftypes.Package{
					{
						Name:       "openssl",
						Version:    "3.0.15",
						Release:    "1~deb12u1",
						SrcName:    "openssl",
						SrcVersion: "3.0.15",
						SrcRelease: "1~deb12u1",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "openssl",
					VulnerabilityID:  "CVE-2025-27587",
					InstalledVersion: "3.0.15-1~deb12u1",
					SeveritySource:   "debian",
					Vulnerability: dbTypes.Vulnerability{
						Severity: "LOW",
					},
					DataSource: &dbTypes.DataSource{
						ID:   "debian",
						Name: "Debian Security Tracker",
						URL:  "https://salsa.debian.org/security-tracker-team/security-tracker",
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

func TestScanner_FilterPackages(t *testing.T) {
	officialPkg := ftypes.Package{
		Name: "openssl",
		Repository: ftypes.PackageRepository{
			Class: ftypes.RepositoryClassOfficial,
		},
	}
	thirdPartyPkg := ftypes.Package{
		Name: "nginx",
		Repository: ftypes.PackageRepository{
			Class: ftypes.RepositoryClassThirdParty,
		},
	}
	sealPkg := ftypes.Package{
		Name: "seal-wget",
		Repository: ftypes.PackageRepository{
			Class: ftypes.RepositoryClassThirdParty,
		},
	}
	sealSrcPkg := ftypes.Package{
		Name:    "wget",
		SrcName: "seal-wget",
		Repository: ftypes.PackageRepository{
			Class: ftypes.RepositoryClassThirdParty,
		},
	}

	tests := []struct {
		name string
		pkgs []ftypes.Package
		want []ftypes.Package
	}{
		{
			name: "Seal package is kept despite being classified as third-party",
			pkgs: []ftypes.Package{sealPkg},
			want: []ftypes.Package{sealPkg},
		},
		{
			name: "Seal package is recognized by SrcName",
			pkgs: []ftypes.Package{sealSrcPkg},
			want: []ftypes.Package{sealSrcPkg},
		},
		{
			name: "base OS package from a third-party repository is dropped",
			pkgs: []ftypes.Package{thirdPartyPkg},
			want: []ftypes.Package{},
		},
		{
			name: "base OS package from an official repository is kept",
			pkgs: []ftypes.Package{officialPkg},
			want: []ftypes.Package{officialPkg},
		},
		{
			name: "package without a repository class is kept",
			pkgs: []ftypes.Package{{Name: "curl"}},
			want: []ftypes.Package{{Name: "curl"}},
		},
		{
			// Seal packages are collected separately, so they come first.
			// The order does not reach the report: it is regrouped in Detect and the
			// result is sorted before output.
			name: "only the base OS packages are filtered",
			pkgs: []ftypes.Package{officialPkg, sealPkg, thirdPartyPkg},
			want: []ftypes.Package{sealPkg, officialPkg},
		},
		{
			name: "no packages",
			pkgs: nil,
			want: []ftypes.Package{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := seal.NewScanner(ftypes.RedHat)
			require.Equal(t, tt.want, s.FilterPackages(t.Context(), tt.pkgs))
		})
	}
}
