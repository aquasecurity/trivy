package wolfi_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/wolfi"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

var source = &dbTypes.DataSource{
	ID:   vulnerability.Wolfi,
	Name: "Wolfi Security Data",
	URL:  "https://advisories.cgr.dev/chainguard/v3/osv/all.json",
}

// TestScanner_Detect covers the wiring between the Wolfi scanner and the
// Wolfi bucket of the database. The detection logic itself is covered in
// the chainguardosv package.
func TestScanner_Detect(t *testing.T) {
	tests := []struct {
		name     string
		fixtures []string
		pkgs     []ftypes.Package
		want     []types.DetectedVulnerability
		wantErr  string
	}{
		{
			name:     "an outdated package is vulnerable",
			fixtures: []string{"testdata/fixtures/wolfi.yaml"},
			pkgs: []ftypes.Package{
				{
					Name:       "glibc",
					Version:    "2.38",
					Release:    "r4",
					SrcName:    "glibc",
					SrcVersion: "2.38",
					SrcRelease: "r4",
					Arch:       "aarch64",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2023-4911",
					VendorIDs:        []string{"CGA-2222-2222-2222"},
					PkgName:          "glibc",
					InstalledVersion: "2.38-r4",
					FixedVersion:     "2.38-r5",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: source,
				},
				{
					// Recorded for x86_64 only, and the feed says nothing about
					// aarch64, so it still applies here.
					VulnerabilityID:  "CVE-2026-12345",
					VendorIDs:        []string{"CGA-3333-3333-3333"},
					PkgName:          "glibc",
					InstalledVersion: "2.38-r4",
					Status:           dbTypes.StatusFixDeferred,
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: source,
				},
				{
					VulnerabilityID:  "CVE-2026-54321",
					VendorIDs:        []string{"CGA-5555-5555-5555"},
					PkgName:          "glibc",
					InstalledVersion: "2.38-r4",
					FixedVersion:     "2.40-r0",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
					DataSource: source,
				},
			},
		},
		{
			name:     "an unresolved advisory is reported with no fixed version",
			fixtures: []string{"testdata/fixtures/wolfi.yaml"},
			pkgs: []ftypes.Package{
				{
					Name:       "glibc",
					Version:    "2.44",
					Release:    "r0",
					SrcName:    "glibc",
					SrcVersion: "2.44",
					SrcRelease: "r0",
					Arch:       "x86_64",
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2026-12345",
					VendorIDs:        []string{"CGA-3333-3333-3333"},
					PkgName:          "glibc",
					InstalledVersion: "2.44-r0",
					Status:           dbTypes.StatusFixDeferred,
					DataSource:       source,
				},
			},
		},
		{
			// The aarch64 build was fixed in 2.40-r0, so 2.41-r0 is not
			// vulnerable even though x86_64 was not fixed until 2.43-r0.
			name:     "the fixed version of the package's architecture is used",
			fixtures: []string{"testdata/fixtures/wolfi.yaml"},
			pkgs: []ftypes.Package{
				{
					Name:       "glibc",
					Version:    "2.41",
					Release:    "r0",
					SrcName:    "glibc",
					SrcVersion: "2.41",
					SrcRelease: "r0",
					Arch:       "aarch64",
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2026-12345",
					VendorIDs:        []string{"CGA-3333-3333-3333"},
					PkgName:          "glibc",
					InstalledVersion: "2.41-r0",
					Status:           dbTypes.StatusFixDeferred,
					DataSource:       source,
				},
			},
		},
		{
			name:     "a subpackage is matched against both its own name and its origin",
			fixtures: []string{"testdata/fixtures/wolfi.yaml"},
			pkgs: []ftypes.Package{
				{
					Name:       "libcrypto3",
					Version:    "3.3.2",
					Release:    "r0",
					SrcName:    "openssl",
					SrcVersion: "3.3.2",
					SrcRelease: "r0",
					Arch:       "x86_64",
				},
			},
			want: []types.DetectedVulnerability{
				{
					// Filed against the origin package openssl.
					VulnerabilityID:  "CVE-2024-9143",
					VendorIDs:        []string{"CGA-4444-4444-4444"},
					PkgName:          "libcrypto3",
					InstalledVersion: "3.3.2-r0",
					FixedVersion:     "3.3.3-r0",
					DataSource:       source,
				},
				{
					// Filed against the subpackage libcrypto3.
					VulnerabilityID:  "CVE-2026-11111",
					VendorIDs:        []string{"CGA-7777-7777-7777"},
					PkgName:          "libcrypto3",
					InstalledVersion: "3.3.2-r0",
					FixedVersion:     "3.6.0-r0",
					DataSource:       source,
				},
			},
		},
		{
			name:     "a broken advisory is an error",
			fixtures: []string{"testdata/fixtures/invalid.yaml"},
			pkgs: []ftypes.Package{
				{
					Name:       "glibc",
					Version:    "2.38",
					Release:    "r4",
					SrcName:    "glibc",
					SrcVersion: "2.38",
					SrcRelease: "r4",
				},
			},
			wantErr: "failed to get Wolfi advisories",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := wolfi.NewScanner()
			got, err := s.Detect(t.Context(), "", nil, tt.pkgs)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestScanner_IsSupportedVersion(t *testing.T) {
	s := wolfi.NewScanner()
	// Wolfi has no distro version, so every input is supported.
	assert.True(t, s.IsSupportedVersion(t.Context(), ftypes.Wolfi, ""))
	assert.True(t, s.IsSupportedVersion(t.Context(), ftypes.Wolfi, "20230214"))
}
