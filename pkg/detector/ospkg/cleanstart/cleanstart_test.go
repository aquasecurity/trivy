package cleanstart_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/cleanstart"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Detect(t *testing.T) {
	type args struct {
		repo *ftypes.Repository
		pkgs []ftypes.Package
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
				"testdata/fixtures/cleanstart.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				pkgs: []ftypes.Package{
					{
						Name:       "redis",
						Version:    "7.4.5-r0",
						SrcName:    "redis",
						SrcVersion: "7.4.5-r0",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
					{
						Name:       "invalid",
						Version:    "invalid",
						SrcName:    "invalid",
						SrcVersion: "invalid",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "redis",
					VulnerabilityID:  "CLEANSTART-2026-MZ27698",
					InstalledVersion: "7.4.5-r0",
					FixedVersion:     "7.4.6-r0",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.CleanStart,
						Name: "CleanStart Security Advisories",
						URL:  "https://github.com/cleanstart-dev/cleanstart-security-advisories",
					},
				},
				{
					PkgName:          "redis",
					VulnerabilityID:  "CVE-2025-12345",
					InstalledVersion: "7.4.5-r0",
					FixedVersion:     "7.4.6-r0",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.CleanStart,
						Name: "CleanStart Security Advisories",
						URL:  "https://github.com/cleanstart-dev/cleanstart-security-advisories",
					},
				},
			},
		},
		{
			name: "no src name",
			fixtures: []string{
				"testdata/fixtures/cleanstart.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				pkgs: []ftypes.Package{
					{
						Name:       "redis",
						Version:    "7.4.5-r0",
						SrcVersion: "7.4.5-r0",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "redis",
					VulnerabilityID:  "CLEANSTART-2026-MZ27698",
					InstalledVersion: "7.4.5-r0",
					FixedVersion:     "7.4.6-r0",
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.CleanStart,
						Name: "CleanStart Security Advisories",
						URL:  "https://github.com/cleanstart-dev/cleanstart-security-advisories",
					},
				},
				{
					PkgName:          "redis",
					VulnerabilityID:  "CVE-2025-12345",
					InstalledVersion: "7.4.5-r0",
					FixedVersion:     "7.4.6-r0",
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.CleanStart,
						Name: "CleanStart Security Advisories",
						URL:  "https://github.com/cleanstart-dev/cleanstart-security-advisories",
					},
				},
			},
		},
		{
			name: "Get returns an error",
			fixtures: []string{
				"testdata/fixtures/invalid.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				pkgs: []ftypes.Package{
					{
						Name:       "redis",
						Version:    "7.4.5-r0",
						SrcName:    "redis",
						SrcVersion: "7.4.5-r0",
					},
				},
			},
			wantErr: "failed to get CleanStart advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := cleanstart.NewScanner()
			got, err := s.Detect(t.Context(), "", tt.args.repo, tt.args.pkgs)
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