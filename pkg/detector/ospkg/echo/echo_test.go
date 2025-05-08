package echo

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/dbtest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Detect(t *testing.T) {
	type args struct {
		pkgs   []ftypes.Package
	}
	tests := []struct {
		name    string
		args    args
		want    []types.DetectedVulnerability
		wantErr string
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
					{ID: "echo", Version: "1.0.0"},
					{ID: "python3", SrcName: "python3", Version: "3.6.8"},
					{ID: "apache2", SrcName: "apache2", Version: "2.4.24"},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2020-11985",
					PkgID:            "apache2",
					InstalledVersion: "2.4.24",
					FixedVersion:     "2.4.25-1",
					Layer:            ftypes.Layer{},
					Vulnerability: dbTypes.Vulnerability{
						Severity: "LOW",
					},
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
					Layer:            ftypes.Layer{},
					Vulnerability: dbTypes.Vulnerability{
						Severity: "MEDIUM",
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
					{ID: "nginx", SrcName: "nginx", Version: "1.14.2", Release: "1ubuntu1"},
					{ID: "apache2", SrcName: "apache2", Version: "2.4.24", Release: "2"},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2020-11985",
					PkgID:            "apache2",
					InstalledVersion: "2.4.24-2",
					FixedVersion:     "2.4.25-1",
					Layer:            ftypes.Layer{},
					Vulnerability: dbTypes.Vulnerability{
						Severity: "LOW",
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
					{ID: "echo", Version: "1.0.0"},
				},
			},
			want: []types.DetectedVulnerability{},
		},
		{
			name: "sad path - invalid",
			fixtures: []string{
				"testdata/fixtures/echo.yaml",
				"testdata/fixtures/invalid.yaml",
			},
			args: args{
				pkgs: []ftypes.Package{
					{SrcName: "apache2", Version: "1.0.0"},
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
