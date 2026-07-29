package rapidfort_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/rapidfort"
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
			name:   "Ubuntu: vulnerable curl, installed version is below fix",
			baseOS: ftypes.Ubuntu,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "22.04",
				pkgs: []ftypes.Package{
					{
						Name:       "curl",
						Version:    "7.81.0-1ubuntu1.13",
						SrcName:    "curl",
						SrcVersion: "7.81.0-1ubuntu1.13",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "curl",
					VulnerabilityID:  "CVE-2023-38039",
					InstalledVersion: "7.81.0-1ubuntu1.13",
					FixedVersion:     "7.81.0-1ubuntu1.14",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "ubuntu",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityMedium.String(),
					},
				},
				{
					PkgName:          "curl",
					VulnerabilityID:  "CVE-2023-38545",
					InstalledVersion: "7.81.0-1ubuntu1.13",
					FixedVersion:     "7.81.0-1ubuntu1.15",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "ubuntu",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
				},
			},
		},
		{
			name:   "Ubuntu: patched curl, installed version is at or above fix",
			baseOS: ftypes.Ubuntu,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "22.04.1", // patch trimmed to "22.04"
				pkgs: []ftypes.Package{
					{
						Name:       "curl",
						Version:    "7.81.0-1ubuntu1.15",
						SrcName:    "curl",
						SrcVersion: "7.81.0-1ubuntu1.15",
					},
				},
			},
			want: nil,
		},
		{
			name:   "Ubuntu: version not in DB returns empty",
			baseOS: ftypes.Ubuntu,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "20.04",
				pkgs: []ftypes.Package{
					{
						Name:       "curl",
						Version:    "7.68.0-1ubuntu2.0",
						SrcName:    "curl",
						SrcVersion: "7.68.0-1ubuntu2.0",
					},
				},
			},
			want: nil,
		},
		{
			name:   "Alpine: vulnerable libssl3",
			baseOS: ftypes.Alpine,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "3.18.4", // trimmed to "3.18"
				pkgs: []ftypes.Package{
					{
						Name:       "libssl3",
						Version:    "3.1.3-r0",
						SrcName:    "libssl3",
						SrcVersion: "3.1.3-r0",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "libssl3",
					VulnerabilityID:  "CVE-2023-5678",
					InstalledVersion: "3.1.3-r0",
					FixedVersion:     "3.1.4-r1",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "alpine",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityMedium.String(),
					},
				},
			},
		},
		{
			name:   "Alpine: patched libssl3",
			baseOS: ftypes.Alpine,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "3.18",
				pkgs: []ftypes.Package{
					{
						Name:       "libssl3",
						Version:    "3.1.4-r1",
						SrcName:    "libssl3",
						SrcVersion: "3.1.4-r1",
					},
				},
			},
			want: nil,
		},
		{
			// el9 package routes to the "rapidfort Red Hat 9" bucket and sees only
			// el9 ranges. The fc39/rf copies of CVE-2023-27536 live in separate
			// buckets, so FixedVersion carries the el9 fix alone.
			name:   "RedHat: vulnerable el9 curl (below el9 fix)",
			baseOS: ftypes.RedHat,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "9.2", // trimmed to "9"
				pkgs: []ftypes.Package{
					{
						Name:       "curl",
						Version:    "7.76.1-20.el9",
						SrcName:    "curl",
						SrcVersion: "7.76.1-20.el9",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "curl",
					VulnerabilityID:  "CVE-2023-27536",
					InstalledVersion: "7.76.1-20.el9",
					FixedVersion:     "7.76.1-26.el9_3.3",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "redhat",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityMedium.String(),
					},
				},
				{
					PkgName:          "curl",
					VulnerabilityID:  "CVE-2024-99999",
					InstalledVersion: "7.76.1-20.el9",
					FixedVersion:     "",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "redhat",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
				},
			},
		},
		{
			// CVE-2023-27536 is patched (installed == el9 patched version).
			// CVE-2024-99999 is an open/unfixed vulnerability and remains reported.
			name:   "RedHat: patched el9 curl (CVE-2023-27536 fixed, CVE-2024-99999 still open)",
			baseOS: ftypes.RedHat,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "9",
				pkgs: []ftypes.Package{
					{
						Name:       "curl",
						Version:    "7.76.1-26.el9_3.3",
						SrcName:    "curl",
						SrcVersion: "7.76.1-26.el9_3.3",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "curl",
					VulnerabilityID:  "CVE-2024-99999",
					InstalledVersion: "7.76.1-26.el9_3.3",
					FixedVersion:     "",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "redhat",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
				},
			},
		},
		{
			// An fc39 package routes to the "rapidfort fedora 39" bucket (not the
			// image's Red Hat 9 bucket), so it sees the fc39 ranges — including the
			// fedora-only advisory — and reports the DataSource with BaseID "fedora".
			name:   "RedHat: fc39 curl routes to the Fedora bucket",
			baseOS: ftypes.RedHat,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "9",
				pkgs: []ftypes.Package{
					{
						Name:       "curl",
						Version:    "7.76.1-20.fc39",
						SrcName:    "curl",
						SrcVersion: "7.76.1-20.fc39",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "curl",
					VulnerabilityID:  "CVE-2023-27536",
					InstalledVersion: "7.76.1-20.fc39",
					FixedVersion:     "7.76.1-26.fc39",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "fedora",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityMedium.String(),
					},
				},
				{
					PkgName:          "curl",
					VulnerabilityID:  "CVE-2024-FC39-ONLY",
					InstalledVersion: "7.76.1-20.fc39",
					FixedVersion:     "7.76.1-26.fc39",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "fedora",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityMedium.String(),
					},
				},
			},
		},
		{
			// A bare .rf rebuild routes to the distribution-less "rapidfort" bucket
			// and matches the rf ranges. The DataSource has no BaseID.
			name:   "RedHat: rf- package with bare .rf suffix routes to the RapidFort bucket",
			baseOS: ftypes.RedHat,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "9",
				pkgs: []ftypes.Package{
					{
						Name:       "rf-curl",
						Version:    "7.76.1-20.rf1",
						SrcName:    "rf-curl",
						SrcVersion: "7.76.1-20.rf1",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "rf-curl",
					VulnerabilityID:  "CVE-2023-27536",
					InstalledVersion: "7.76.1-20.rf1",
					FixedVersion:     "7.76.1-26.rf1",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:   "rapidfort",
						Name: "RapidFort Security Advisories",
						URL:  "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityMedium.String(),
					},
				},
			},
		},
		{
			// An untagged RPM (no el/fc/rf dist tag) routes to the base Red Hat
			// bucket keyed by the image's OS version, matching the el9 advisories there.
			name:   "RedHat: untagged RPM routes to the base Red Hat bucket",
			baseOS: ftypes.RedHat,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "9",
				pkgs: []ftypes.Package{
					{
						Name:       "curl",
						Version:    "7.76.1-20",
						SrcName:    "curl",
						SrcVersion: "7.76.1-20",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "curl",
					VulnerabilityID:  "CVE-2023-27536",
					InstalledVersion: "7.76.1-20",
					FixedVersion:     "7.76.1-26.el9_3.3",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "redhat",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityMedium.String(),
					},
				},
				{
					PkgName:          "curl",
					VulnerabilityID:  "CVE-2024-99999",
					InstalledVersion: "7.76.1-20",
					FixedVersion:     "",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "redhat",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
				},
			},
		},
		{
			// Source→binary fallback: rpm-sequoia is the installed binary,
			// rust-rpm-sequoia is its SRPM. CVE-2025-0977 lives in the SRPM
			// bucket (primary lookup). CVE-2026-2625 lives in the binary
			// bucket (must be picked up by the fallback). CVE-2025-OVERLAP
			// is present in both buckets — dedupe must keep the SRPM entry
			// (Severity High, fix 1.9.0-1.el9), not the binary one.
			name:   "RedHat: source→binary fallback picks up binary-keyed advisory",
			baseOS: ftypes.RedHat,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "9",
				pkgs: []ftypes.Package{
					{
						Name:       "rpm-sequoia",
						Version:    "1.0.0-1.el9",
						SrcName:    "rust-rpm-sequoia",
						SrcVersion: "1.0.0-1.el9",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "rpm-sequoia",
					VulnerabilityID:  "CVE-2025-0977",
					InstalledVersion: "1.0.0-1.el9",
					FixedVersion:     "1.8.0-2.el9",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "redhat",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
				},
				{
					PkgName:          "rpm-sequoia",
					VulnerabilityID:  "CVE-2025-OVERLAP",
					InstalledVersion: "1.0.0-1.el9",
					// SRPM entry wins on dedupe: fix = 1.9.0-1.el9, not 99.99.99-1.el9.
					FixedVersion:   "1.9.0-1.el9",
					SeveritySource: "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "redhat",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						// SRPM entry wins: High, not Low from the binary bucket.
						Severity: dbTypes.SeverityHigh.String(),
					},
				},
				{
					PkgName:          "rpm-sequoia",
					VulnerabilityID:  "CVE-2026-2625",
					InstalledVersion: "1.0.0-1.el9",
					FixedVersion:     "1.10.0-1.el9",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "redhat",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityMedium.String(),
					},
				},
			},
		},
		{
			// When pkg.Name == pkg.SrcName the binary bucket must NOT be
			// queried. CVE-2026-2625 lives only in the rpm-sequoia bucket;
			// for an installed package whose Name and SrcName both equal
			// rust-rpm-sequoia, it must not surface.
			name:   "RedHat: no fallback when Name == SrcName (binary bucket not queried)",
			baseOS: ftypes.RedHat,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "9",
				pkgs: []ftypes.Package{
					{
						Name:       "rust-rpm-sequoia",
						Version:    "1.0.0-1.el9",
						SrcName:    "rust-rpm-sequoia",
						SrcVersion: "1.0.0-1.el9",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "rust-rpm-sequoia",
					VulnerabilityID:  "CVE-2025-0977",
					InstalledVersion: "1.0.0-1.el9",
					FixedVersion:     "1.8.0-2.el9",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "redhat",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
				},
				{
					PkgName:          "rust-rpm-sequoia",
					VulnerabilityID:  "CVE-2025-OVERLAP",
					InstalledVersion: "1.0.0-1.el9",
					FixedVersion:     "1.9.0-1.el9",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "redhat",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
				},
			},
		},
		{
			// SrcName empty → falls back to pkg.Name internally (existing behavior).
			// pkg.Name == derived srcName so the binary-name fallback must NOT
			// fire — CVE-2025-0977 (only in the rust-rpm-sequoia bucket) must
			// not appear.
			name:   "RedHat: empty SrcName falls back to Name, no second lookup",
			baseOS: ftypes.RedHat,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "9",
				pkgs: []ftypes.Package{
					{
						Name:       "rpm-sequoia",
						Version:    "1.0.0-1.el9",
						SrcVersion: "1.0.0-1.el9",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "rpm-sequoia",
					VulnerabilityID:  "CVE-2025-OVERLAP",
					InstalledVersion: "1.0.0-1.el9",
					// Only the rpm-sequoia bucket entry is seen here.
					FixedVersion:   "99.99.99-1.el9",
					SeveritySource: "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "redhat",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityLow.String(),
					},
				},
				{
					PkgName:          "rpm-sequoia",
					VulnerabilityID:  "CVE-2026-2625",
					InstalledVersion: "1.0.0-1.el9",
					FixedVersion:     "1.10.0-1.el9",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "redhat",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityMedium.String(),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			scanner := rapidfort.NewScanner(tt.baseOS)
			got, err := scanner.Detect(t.Context(), tt.args.osVer, nil, tt.args.pkgs)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			// Sort results for stable comparison since map iteration order is not deterministic
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestSupplier(t *testing.T) {
	tests := []struct {
		name    string
		os      ftypes.OS
		wantNil bool
	}{
		{
			name:    "RapidFort Ubuntu image detected",
			os:      ftypes.OS{Family: ftypes.Ubuntu, Supplier: ftypes.SupplierRapidFort},
			wantNil: false,
		},
		{
			name:    "RapidFort Alpine image detected",
			os:      ftypes.OS{Family: ftypes.Alpine, Supplier: ftypes.SupplierRapidFort},
			wantNil: false,
		},
		{
			name:    "RapidFort RedHat image detected",
			os:      ftypes.OS{Family: ftypes.RedHat, Supplier: ftypes.SupplierRapidFort},
			wantNil: false,
		},
		{
			name:    "No RapidFort supplier returns nil",
			os:      ftypes.OS{Family: ftypes.Ubuntu},
			wantNil: true,
		},
		{
			name:    "Different supplier returns nil",
			os:      ftypes.OS{Family: ftypes.Ubuntu, Supplier: ftypes.SupplierSeal},
			wantNil: true,
		},
		{
			name:    "RapidFort supplier on unsupported OS family returns nil",
			os:      ftypes.OS{Family: ftypes.Debian, Supplier: ftypes.SupplierRapidFort},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := rapidfort.Supplier(tt.os, nil)
			if tt.wantNil {
				assert.Nil(t, d)
			} else {
				assert.NotNil(t, d)
			}
		})
	}
}

func TestScanner_IsVulnerable(t *testing.T) {
	// Covers the version-comparison logic: the patched-equality shortcut, empty
	// ranges meaning "all versions vulnerable", and range membership.
	tests := []struct {
		name             string
		baseOS           ftypes.OSType
		installedVersion string
		vulnerableRanges []string
		patchedVersions  []string
		want             bool
	}{
		{
			name:             "No version constraint: always vulnerable",
			baseOS:           ftypes.Ubuntu,
			installedVersion: "7.81.0-1ubuntu1.13",
			vulnerableRanges: []string{},
			want:             true,
		},
		{
			name:             "Empty installed version: not vulnerable",
			baseOS:           ftypes.Ubuntu,
			installedVersion: "",
			vulnerableRanges: []string{">= 0, < 7.81.0-1ubuntu1.15"},
			want:             false,
		},
		{
			name:             "Vulnerable: below fix (introduced=0 format from pipeline)",
			baseOS:           ftypes.Ubuntu,
			installedVersion: "7.81.0-1ubuntu1.13",
			vulnerableRanges: []string{">= 0, < 7.81.0-1ubuntu1.15"},
			want:             true,
		},
		{
			name:             "Patched: at fix version",
			baseOS:           ftypes.Ubuntu,
			installedVersion: "7.81.0-1ubuntu1.15",
			vulnerableRanges: []string{">= 0, < 7.81.0-1ubuntu1.15"},
			want:             false,
		},
		{
			name:             "Patched: above fix version",
			baseOS:           ftypes.Ubuntu,
			installedVersion: "7.81.0-1ubuntu1.16",
			vulnerableRanges: []string{">= 0, < 7.81.0-1ubuntu1.15"},
			want:             false,
		},
		{
			name:             "Range constraint: specific introduced version",
			baseOS:           ftypes.Ubuntu,
			installedVersion: "7.81.0-1ubuntu1.13",
			vulnerableRanges: []string{">= 7.0.0, < 7.81.0-1ubuntu1.15"},
			want:             true,
		},
		{
			name:             "Alpine: APK version comparison",
			baseOS:           ftypes.Alpine,
			installedVersion: "3.1.3-r0",
			vulnerableRanges: []string{">= 0, < 3.1.4-r1"},
			want:             true,
		},
		{
			name:             "Fixed-version-first: installed equals patched, not vulnerable even if range would include it",
			baseOS:           ftypes.Ubuntu,
			installedVersion: "7.81.0-1ubuntu1.15",
			vulnerableRanges: []string{">= 0, < 7.81.0-1ubuntu1.16"},
			patchedVersions:  []string{"7.81.0-1ubuntu1.15"},
			want:             false,
		},
		{
			name:             "RedHat el9: vulnerable — installed below el9 fix",
			baseOS:           ftypes.RedHat,
			installedVersion: "7.76.1-20.el9",
			vulnerableRanges: []string{">= 7.76.1-14.el9, < 7.76.1-26.el9_3.3"},
			want:             true,
		},
		{
			name:             "RedHat el9: not vulnerable — installed at el9 fix",
			baseOS:           ftypes.RedHat,
			installedVersion: "7.76.1-26.el9_3.3",
			vulnerableRanges: []string{">= 7.76.1-14.el9, < 7.76.1-26.el9_3.3"},
			patchedVersions:  []string{"7.76.1-26.el9_3.3"},
			want:             false,
		},
		{
			name:             "RedHat: open-ended vulnerability (no fix)",
			baseOS:           ftypes.RedHat,
			installedVersion: "7.76.1-20.el9",
			vulnerableRanges: []string{">=7.76.1-14.el9"},
			want:             true,
		},
		{
			// A malformed range must be skipped, not abort the loop: a later
			// valid range still decides the result.
			name:             "Malformed range is skipped; a later valid range still matches",
			baseOS:           ftypes.Ubuntu,
			installedVersion: "1.0",
			vulnerableRanges: []string{"not-a-constraint", ">= 0, < 2.0"},
			want:             true,
		},
		{
			name:             "Only a malformed range: not vulnerable",
			baseOS:           ftypes.Ubuntu,
			installedVersion: "1.0",
			vulnerableRanges: []string{"not-a-constraint"},
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := rapidfort.NewScanner(tt.baseOS)
			adv := dbTypes.Advisory{
				VulnerableVersions: tt.vulnerableRanges,
				PatchedVersions:    tt.patchedVersions,
			}
			result := scanner.IsVulnerable(t.Context(), tt.installedVersion, adv)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestRpmDistTag(t *testing.T) {
	tests := []struct {
		ver     string
		wantTag string
		wantNum string
	}{
		{ver: "7.76.1-26.el9_3.3", wantTag: "el", wantNum: "9"},
		{ver: "7.76.1-26.fc43", wantTag: "fc", wantNum: "43"},
		{ver: "7.76.1-20.rf1", wantTag: "rf", wantNum: "1"},
		{ver: "7.76.1-26.rf", wantTag: "rf", wantNum: ""},
		// The dist tag is the trailing one: a ".rf" inside "rfc3339" must not win.
		{ver: "1.0-1.rfc3339.el9", wantTag: "el", wantNum: "9"},
		// Composite release: the last tag wins.
		{ver: "7.76.1-26.rf1.el9", wantTag: "el", wantNum: "9"},
		// Untagged / non-RPM versions have no dist tag.
		{ver: "1.0.0-1", wantTag: "", wantNum: ""},
		{ver: "3.1.4-r1", wantTag: "", wantNum: ""},
	}
	for _, tt := range tests {
		t.Run(tt.ver, func(t *testing.T) {
			tag, num := rapidfort.RpmDistTag(tt.ver)
			assert.Equal(t, tt.wantTag, tag)
			assert.Equal(t, tt.wantNum, num)
		})
	}
}

func TestScanner_FilterPackages(t *testing.T) {
	// RapidFort curates advisories for every package it ships, including
	// third-party ones, so FilterPackages keeps them all unchanged.
	pkgs := []ftypes.Package{
		{
			Name: "curl",
			Repository: ftypes.PackageRepository{
				Class: ftypes.RepositoryClassThirdParty,
			},
		},
		{
			Name: "nginx",
		},
		{
			Name: "rf-glibc",
		},
	}

	s := rapidfort.NewScanner(ftypes.RedHat)
	assert.Equal(t, pkgs, s.FilterPackages(t.Context(), pkgs))
}
