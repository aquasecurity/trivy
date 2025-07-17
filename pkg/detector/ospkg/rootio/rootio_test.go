package rootio_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/rootio"
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
				"testdata/fixtures/rootio.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "12",
				pkgs: []ftypes.Package{
					{
						Name:       "openssl",
						Version:    "3.0.15-1~deb12u1.root.io.0",
						SrcName:    "openssl",
						SrcVersion: "3.0.15-1~deb12u1.root.io.0",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "openssl",
					VulnerabilityID:  "CVE-2024-13176", // Debian and Root.io contain this CVE
					InstalledVersion: "3.0.15-1~deb12u1.root.io.0",
					FixedVersion:     "3.0.15-1~deb12u1.root.io.1, 3.0.16-1~deb12u1",
					SeveritySource:   vulnerability.Debian,
					DataSource: &dbTypes.DataSource{
						ID:     vulnerability.RootIO,
						BaseID: vulnerability.Debian,
						Name:   "Root.io Security Patches (debian)",
						URL:    "https://api.root.io/external/patch_feed",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityMedium.String(),
					},
				},
				{
					PkgName:          "openssl",
					VulnerabilityID:  "CVE-2025-27587", // Debian only contains this CVE
					InstalledVersion: "3.0.15-1~deb12u1.root.io.0",
					FixedVersion:     "3.0.16-1~deb12u1",
					SeveritySource:   vulnerability.Debian,
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Debian,
						Name: "Debian Security Tracker",
						URL:  "https://salsa.debian.org/security-tracker-team/security-tracker",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityLow.String(),
					},
				},
			},
		},
		{
			name:   "Ubuntu scanner",
			baseOS: ftypes.Ubuntu,
			fixtures: []string{
				"testdata/fixtures/rootio.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "20.04",
				pkgs: []ftypes.Package{
					{
						Name:       "nginx",
						Version:    "1.22.1-9+deb12u2.root.io.0",
						SrcName:    "nginx",
						SrcVersion: "1.22.1-9+deb12u2.root.io.0",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "nginx",
					VulnerabilityID:  "CVE-2023-44487",
					InstalledVersion: "1.22.1-9+deb12u2.root.io.0",
					FixedVersion:     "1.22.1-9+deb12u2.root.io.1",
					DataSource: &dbTypes.DataSource{
						ID:     vulnerability.RootIO,
						BaseID: vulnerability.Ubuntu,
						Name:   "Root.io Security Patches (ubuntu)",
						URL:    "https://api.root.io/external/patch_feed",
					},
				},
			},
		},
		{
			name:   "Rocky scanner",
			baseOS: ftypes.Rocky,
			fixtures: []string{
				"testdata/fixtures/rootio.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "8.9",
				pkgs: []ftypes.Package{
					{
						Name:       "nginx",
						Version:    "1.22.1-9+rocky8.9.root.io.0",
						SrcName:    "nginx",
						SrcVersion: "1.22.1-9+rocky8.9.root.io.0",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "nginx",
					VulnerabilityID:  "CVE-2023-44487",
					InstalledVersion: "1.22.1-9+rocky8.9.root.io.0",
					FixedVersion:     "1.22.1-9+rocky8.9.root.io.1",
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.RootIO,
						Name: "Root.io Security Patches",
						URL:  "https://api.root.io/external/patch_feed",
					},
				},
			},
		},
		{
			name:   "Alpine scanner",
			baseOS: ftypes.Alpine,
			fixtures: []string{
				"testdata/fixtures/rootio.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "3.19.3",
				pkgs: []ftypes.Package{
					{
						Name:       "less",
						Version:    "643-r00072",
						SrcName:    "less",
						SrcVersion: "643-r00072",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "less",
					VulnerabilityID:  "CVE-2024-32487",
					InstalledVersion: "643-r00072",
					FixedVersion:     "643-r10072",
					DataSource: &dbTypes.DataSource{
						ID:     vulnerability.RootIO,
						BaseID: vulnerability.Alpine,
						Name:   "Root.io Security Patches (alpine)",
						URL:    "https://api.root.io/external/patch_feed",
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
						Name:       "jq",
						Version:    "1.5-12",
						SrcName:    "jq",
						SrcVersion: "1.5-12",
					},
				},
			},
			wantErr: "failed to get Root.io advisories",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			scanner := rootio.NewScanner(tt.baseOS)
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
