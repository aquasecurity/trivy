package bottlerocket_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/bottlerocket"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Detect(t *testing.T) {
	tests := []struct {
		name     string
		fixtures []string
		pkgs     []ftypes.Package
		want     []types.DetectedVulnerability
		wantErr  string
	}{
		{
			name: "vulnerable kernel",
			fixtures: []string{
				"testdata/fixtures/bottlerocket.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			pkgs: []ftypes.Package{
				{
					Name:    "kernel-6.1",
					Version: "6.1.50",
					Release: "1.1690000000.br1",
					Epoch:   0,
					Layer: ftypes.Layer{
						DiffID: "sha256:aaa",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "kernel-6.1",
					VulnerabilityID:  "CVE-2023-5345",
					InstalledVersion: "6.1.50-1.1690000000.br1",
					FixedVersion:     "6.1.61-1.1700513487.br1",
					Layer: ftypes.Layer{
						DiffID: "sha256:aaa",
					},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Bottlerocket,
						Name: "Bottlerocket Security Advisories",
						URL:  "https://advisories.bottlerocket.aws/",
					},
				},
			},
		},
		{
			name: "not vulnerable - installed version is newer",
			fixtures: []string{
				"testdata/fixtures/bottlerocket.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			pkgs: []ftypes.Package{
				{
					Name:    "kernel-6.1",
					Version: "6.1.70",
					Release: "1.1710000000.br1",
					Epoch:   0,
				},
			},
			want: nil,
		},
		{
			name: "vulnerable package with epoch",
			fixtures: []string{
				"testdata/fixtures/bottlerocket.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			pkgs: []ftypes.Package{
				{
					Name:    "glibc",
					Version: "2.40",
					Release: "1.1740525475.e3a5862c.br1",
					Epoch:   1,
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "glibc",
					VulnerabilityID:  "CVE-2024-99999",
					InstalledVersion: "1:2.40-1.1740525475.e3a5862c.br1",
					FixedVersion:     "1:2.41-1.1760000000.aaaaaaaa.br1",
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.Bottlerocket,
						Name: "Bottlerocket Security Advisories",
						URL:  "https://advisories.bottlerocket.aws/",
					},
				},
			},
		},
		{
			name: "no packages",
			fixtures: []string{
				"testdata/fixtures/bottlerocket.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			pkgs: nil,
			want: nil,
		},
		{
			name: "Get returns an error",
			fixtures: []string{
				"testdata/fixtures/invalid.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			pkgs: []ftypes.Package{
				{
					Name:    "kernel-6.1",
					Version: "6.1.50",
					Release: "1.1690000000.br1",
				},
			},
			wantErr: "failed to get Bottlerocket advisories",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := bottlerocket.NewScanner()
			got, err := s.Detect(t.Context(), "", nil, tt.pkgs)
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

func TestScanner_IsSupportedVersion(t *testing.T) {
	s := bottlerocket.NewScanner()
	assert.True(t, s.IsSupportedVersion(t.Context(), ftypes.Bottlerocket, "1.19.0"))
}
