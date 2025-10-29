package echo

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/internal/dbtest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Detect(t *testing.T) {
	type args struct {
		pkgs []ftypes.Package
	}
	tests := []struct {
		name     string
		args     args
		want     []types.DetectedVulnerability
		wantErr  string
		fixtures []string
	}{
		{
			name: "happy path - detect vulnerabilities",
			fixtures: []string{
				"testdata/fixtures/echo.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				pkgs: []ftypes.Package{
					{
						ID:         "echo",
						Name:       "echo",
						Version:    "1.0.0",
						SrcName:    "echo",
						SrcVersion: "1.0.0",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
					{
						ID:         "python3",
						Name:       "python3",
						Version:    "3.6.8",
						SrcName:    "python3",
						SrcVersion: "3.6.8",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
					{
						ID:         "apache2",
						Name:       "htpasswd",
						SrcName:    "apache2",
						Version:    "2.4.24",
						SrcVersion: "2.4.24",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2020-11985",
					PkgID:            "apache2",
					InstalledVersion: "2.4.24",
					FixedVersion:     "2.4.25-1",
					PkgName:          "htpasswd",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: "LOW",
					},
					SeveritySource: vulnerability.Echo,
					DataSource: &dbTypes.DataSource{
						ID:   "echo",
						Name: "Echo",
						URL:  "https://advisory.echohq.com/data.json",
					},
				},
				{
					VulnerabilityID:  "CVE-2020-26116",
					PkgID:            "python3",
					InstalledVersion: "3.6.8",
					FixedVersion:     "3.6.9",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: "MEDIUM",
					},
					PkgName:        "python3",
					SeveritySource: vulnerability.Echo,
					DataSource: &dbTypes.DataSource{
						ID:   "echo",
						Name: "Echo",
						URL:  "https://advisory.echohq.com/data.json",
					},
				},
				{
					VulnerabilityID:  "CVE-2021-11111",
					PkgID:            "apache2",
					InstalledVersion: "2.4.24",
					FixedVersion:     "2.4.25-1",
					PkgName:          "htpasswd",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   "echo",
						Name: "Echo",
						URL:  "https://advisory.echohq.com/data.json",
					},
				},
				{
					VulnerabilityID:  "CVE-2021-11113",
					PkgID:            "apache2",
					InstalledVersion: "2.4.24",
					FixedVersion:     "",
					PkgName:          "htpasswd",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   "echo",
						Name: "Echo",
						URL:  "https://advisory.echohq.com/data.json",
					},
				},
			},
		},
		{
			name: "happy path - package with release",
			fixtures: []string{
				"testdata/fixtures/echo.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				pkgs: []ftypes.Package{
					{
						ID:         "nginx",
						Name:       "nginx",
						Version:    "1.14.2",
						SrcName:    "nginx",
						SrcVersion: "1.14.2",
						Release:    "1ubuntu1",
						SrcRelease: "1ubuntu1",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
					{
						ID:         "apache2",
						Name:       "apache2",
						SrcName:    "apache2",
						Version:    "2.4.24",
						SrcVersion: "2.4.24",
						Release:    "2",
						SrcRelease: "2",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2020-11985",
					PkgID:            "apache2",
					InstalledVersion: "2.4.24-2",
					FixedVersion:     "2.4.25-1",
					PkgName:          "apache2",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: "LOW",
					},
					SeveritySource: vulnerability.Echo,
					DataSource: &dbTypes.DataSource{
						ID:   "echo",
						Name: "Echo",
						URL:  "https://advisory.echohq.com/data.json",
					},
				},
				{
					VulnerabilityID:  "CVE-2021-11111",
					PkgID:            "apache2",
					InstalledVersion: "2.4.24-2",
					FixedVersion:     "2.4.25-1",
					PkgName:          "apache2",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   "echo",
						Name: "Echo",
						URL:  "https://advisory.echohq.com/data.json",
					},
				},

				{
					VulnerabilityID:  "CVE-2021-11113",
					PkgID:            "apache2",
					InstalledVersion: "2.4.24-2",
					FixedVersion:     "",
					PkgName:          "apache2",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   "echo",
						Name: "Echo",
						URL:  "https://advisory.echohq.com/data.json",
					},
				},
			},
		},
		{
			name: "happy path - no matching packages",
			args: args{
				pkgs: []ftypes.Package{
					{ID: "echo", Version: "1.0.0", SrcVersion: "1.0.0", SrcName: "echo"},
				},
			},
			want: nil,
		},
		{
			name: "sad path - invalid",
			fixtures: []string{
				"testdata/fixtures/echo.yaml",
				"testdata/fixtures/invalid.yaml",
			},
			args: args{
				pkgs: []ftypes.Package{
					{SrcName: "apache2", Version: "1.0.0", SrcVersion: "1.0.0"},
				},
			},
			wantErr: "failed to get echo advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := NewScanner()
			got, err := s.Detect(t.Context(), "", nil, tt.args.pkgs)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			sort.Slice(got, func(i, j int) bool {
				return got[i].VulnerabilityID < got[j].VulnerabilityID
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
