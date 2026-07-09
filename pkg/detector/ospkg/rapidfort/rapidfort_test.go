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
					FixedVersion:     "7.76.1-26.el9_3.3, 7.76.1-26.fc39",
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
			// CVE-2023-27536 is patched (installed == patched version).
			// CVE-2024-99999 is an open/unfixed vulnerability and remains reported.
			// CVE-2024-FC39-ONLY is fc39-only and must NOT appear for an el9 package.
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
			// CVE-2024-FC39-ONLY has only an fc39 range; an el9 package must not be flagged
			// even though the version satisfies the fc39 range numerically under RPM ordering.
			name:   "RedHat: el9 curl not affected by fc39-only advisory (identifier filtering)",
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
						Version:    "7.76.1-20.el9",
						SrcName:    "curl",
						SrcVersion: "7.76.1-20.el9",
					},
				},
			},
			// CVE-2023-27536 and CVE-2024-99999 appear (el9 ranges match).
			// CVE-2024-FC39-ONLY must NOT appear (fc39 identifier filtered out).
			want: []types.DetectedVulnerability{
				{
					PkgName:          "curl",
					VulnerabilityID:  "CVE-2023-27536",
					InstalledVersion: "7.76.1-20.el9",
					FixedVersion:     "7.76.1-26.el9_3.3, 7.76.1-26.fc39",
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
			name:   "RedHat: rf- package name stripped, el9 version identified",
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
						Version:    "7.76.1-20.el9",
						SrcName:    "rf-curl",
						SrcVersion: "7.76.1-20.el9",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "rf-curl",
					VulnerabilityID:  "CVE-2023-27536",
					InstalledVersion: "7.76.1-20.el9",
					FixedVersion:     "7.76.1-26.el9_3.3, 7.76.1-26.fc39, 7.76.1-26.rf1",
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
					PkgName:          "rf-curl",
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
			name:   "RedHat: rf package with bare .rf suffix uses 'rf' identifier",
			baseOS: ftypes.RedHat,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "9",
				pkgs: []ftypes.Package{
					{
						// Version has no el/fc tag; uses "rf" identifier to match rf-tagged ranges.
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
					FixedVersion:     "7.76.1-26.el9_3.3, 7.76.1-26.fc39, 7.76.1-26.rf1",
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
					PkgName:          "rf-curl",
					VulnerabilityID:  "CVE-2024-99999",
					InstalledVersion: "7.76.1-20.rf1",
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

func TestProvider(t *testing.T) {
	tests := []struct {
		name     string
		osFamily ftypes.OSType
		labels   map[string]string
		wantNil  bool
	}{
		{
			name:     "RapidFort Ubuntu image detected",
			osFamily: ftypes.Ubuntu,
			labels: map[string]string{
				"maintainer": "RapidFort Curation Team <rfcurators@rapidfort.com>",
			},
			wantNil: false,
		},
		{
			name:     "RapidFort Alpine image detected",
			osFamily: ftypes.Alpine,
			labels: map[string]string{
				"maintainer": "RapidFort Curation Team <rfcurators@rapidfort.com>",
			},
			wantNil: false,
		},
		{
			name:     "Non-RapidFort image: no maintainer label",
			osFamily: ftypes.Ubuntu,
			labels:   make(map[string]string),
			wantNil:  true,
		},
		{
			name:     "Non-RapidFort image: different maintainer",
			osFamily: ftypes.Ubuntu,
			labels: map[string]string{
				"maintainer": "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
			},
			wantNil: true,
		},
		{
			name:     "RapidFort RedHat image detected",
			osFamily: ftypes.RedHat,
			labels: map[string]string{
				"maintainer": "RapidFort Curation Team <rfcurators@rapidfort.com>",
			},
			wantNil: false,
		},
		{
			name:     "Case-insensitive detection",
			osFamily: ftypes.Ubuntu,
			labels: map[string]string{
				"maintainer": "RAPIDFORT curation team",
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := rapidfort.Provider(tt.osFamily, nil, tt.labels)
			if tt.wantNil {
				assert.Nil(t, d)
			} else {
				assert.NotNil(t, d)
			}
		})
	}
}

func TestScanner_IsVulnerable(t *testing.T) {
	// Note: the distro identifier is no longer a test input — it's derived
	// internally from installedVersion inside isRPMVulnerable. Each RedHat
	// test case's installedVersion is chosen so that the derived identifier
	// matches the scenario being exercised (e.g. ".el9" → "el9", ".rf1" →
	// "rf", no distro tag → defaults to "el").
	tests := []struct {
		name             string
		baseOS           ftypes.OSType
		installedVersion string
		isRFPackage      bool
		vulnerableRanges []string
		patchedVersions  []string
		custom           any
		want             bool
	}{
		// ── Ubuntu / Alpine (no identifier) ─────────────────────────────────────
		{
			name:             "No version constraint: always vulnerable",
			baseOS:           ftypes.Ubuntu,
			installedVersion: "7.81.0-1ubuntu1.13",
			vulnerableRanges: []string{},
			want:             true,
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
		// ── RedHat: identifier-based filtering ──────────────────────────────────
		{
			name:             "RPM el9: vulnerable — el9 range matches installed identifier",
			baseOS:           ftypes.RedHat,
			installedVersion: "7.76.1-20.el9",
			vulnerableRanges: []string{
				">= 7.76.1-14.el9, < 7.76.1-26.el9_3.3",
				">= 7.76.1-14.fc39, < 7.76.1-26.fc39",
			},
			custom: map[string]any{"identifiers": []any{"el9", "fc39"}},
			want:   true,
		},
		{
			name:             "RPM el9: not vulnerable — fc39 range skipped, el9 range not satisfied",
			baseOS:           ftypes.RedHat,
			installedVersion: "7.76.1-26.el9_3.3",
			vulnerableRanges: []string{
				">= 7.76.1-14.el9, < 7.76.1-26.el9_3.3",
				">= 7.76.1-14.fc39, < 7.76.1-26.fc39",
			},
			patchedVersions: []string{"7.76.1-26.el9_3.3", "7.76.1-26.fc39"},
			custom:          map[string]any{"identifiers": []any{"el9", "fc39"}},
			want:            false,
		},
		{
			name:             "RPM el9: fc39 range must not cause false positive for el9 package",
			baseOS:           ftypes.RedHat,
			installedVersion: "7.76.1-20.el9",
			// Only fc39 ranges present — el9 package must not be flagged.
			vulnerableRanges: []string{">= 7.76.1-14.fc39, < 7.76.1-26.fc39"},
			custom:           map[string]any{"identifiers": []any{"fc39"}},
			want:             false,
		},
		{
			name:             "RPM fc39: vulnerable — fc39 range matches installed identifier",
			baseOS:           ftypes.RedHat,
			installedVersion: "7.76.1-20.fc39",
			vulnerableRanges: []string{
				">= 7.76.1-14.el9, < 7.76.1-26.el9_3.3",
				">= 7.76.1-14.fc39, < 7.76.1-26.fc39",
			},
			custom: map[string]any{"identifiers": []any{"el9", "fc39"}},
			want:   true,
		},
		{
			// installedVersion has no el/fc tag and no .rf suffix, so the derived
			// identifier is "" and defaults to "el". "el" prefix-matches "el9",
			// so the el9 advisory range is checked.
			name:             "RPM: no identifier in version — defaults to 'el', matches el9 advisory range",
			baseOS:           ftypes.RedHat,
			installedVersion: "7.76.1-20",
			vulnerableRanges: []string{">= 7.76.1-14.el9, < 7.76.1-26.el9_3.3"},
			custom:           map[string]any{"identifiers": []any{"el9"}},
			want:             true,
		},
		{
			// Same as above: derived identifier defaults to "el" and must NOT
			// prefix-match an fc-only advisory range.
			name:             "RPM: no identifier in version — defaults to 'el', fc39 range must be skipped",
			baseOS:           ftypes.RedHat,
			installedVersion: "7.76.1-20",
			vulnerableRanges: []string{">= 7.76.1-14.fc39, < 7.76.1-26.fc39"},
			custom:           map[string]any{"identifiers": []any{"fc39"}},
			want:             false,
		},
		{
			name:             "RPM: open-ended vulnerability (no fix) with el9 identifier",
			baseOS:           ftypes.RedHat,
			installedVersion: "7.76.1-20.el9",
			vulnerableRanges: []string{">=7.76.1-14.el9"},
			custom:           map[string]any{"identifiers": []any{"el9"}},
			want:             true,
		},
		// ── RedHat: "rf" identifier (.rf suffix versions) ───────────────────────
		{
			name:             "RPM rf: .rf version matches 'rf' advisory range",
			baseOS:           ftypes.RedHat,
			installedVersion: "7.76.1-20.rf1",
			vulnerableRanges: []string{
				">= 7.76.1-14.el9, < 7.76.1-26.el9_3.3",
				">= 7.76.1-14.fc39, < 7.76.1-26.fc39",
				">= 7.76.1-14.rf, < 7.76.1-26.rf1",
			},
			custom: map[string]any{"identifiers": []any{"el9", "fc39", "rf"}},
			want:   true,
		},
		{
			name:             "RPM rf: .rf version must not match el9/fc39-only ranges",
			baseOS:           ftypes.RedHat,
			installedVersion: "7.76.1-20.rf1",
			vulnerableRanges: []string{
				">= 7.76.1-14.el9, < 7.76.1-26.el9_3.3",
				">= 7.76.1-14.fc39, < 7.76.1-26.fc39",
			},
			custom: map[string]any{"identifiers": []any{"el9", "fc39"}},
			want:   false,
		},
		// ── RedHat: rf- package fallback ─────────────────────────────────────────
		{
			// rf- package with fc43 version; advisory has only "rf" ranges.
			// No primary identifier match → fallback includes "rf" range.
			name:             "RPM rf- fallback: fc43 package matches 'rf' range when no fc43 range exists",
			baseOS:           ftypes.RedHat,
			installedVersion: "2.7.3-1.fc43",
			isRFPackage:      true,
			vulnerableRanges: []string{">= 2.7.0-1.rf, < 2.7.4-1.rf1"},
			custom:           map[string]any{"identifiers": []any{"rf"}},
			want:             true,
		},
		{
			// rf- package with fc43 version; advisory has fc43 range → primary match,
			// fallback must not fire.
			name:             "RPM rf- fallback: fc43 range present, primary match used — no fallback",
			baseOS:           ftypes.RedHat,
			installedVersion: "2.7.3-1.fc43",
			isRFPackage:      true,
			vulnerableRanges: []string{
				">= 2.7.0-1.fc43, < 2.7.4-1.fc43",
				">= 2.7.0-1.rf, < 2.7.4-1.rf1",
			},
			custom: map[string]any{"identifiers": []any{"fc43", "rf"}},
			want:   true,
		},
		{
			// Non-rf package with fc43 version; advisory has only "rf" ranges.
			// Fallback must NOT fire for non-rf packages.
			name:             "RPM rf- fallback: non-rf package must not match 'rf'-only range",
			baseOS:           ftypes.RedHat,
			installedVersion: "2.7.3-1.fc43",
			isRFPackage:      false,
			vulnerableRanges: []string{">= 2.7.0-1.rf, < 2.7.4-1.rf1"},
			custom:           map[string]any{"identifiers": []any{"rf"}},
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := rapidfort.NewScanner(tt.baseOS)
			adv := dbTypes.Advisory{
				VulnerableVersions: tt.vulnerableRanges,
				PatchedVersions:    tt.patchedVersions,
				Custom:             tt.custom,
			}
			result := scanner.IsVulnerable(t.Context(), tt.installedVersion, tt.isRFPackage, adv)
			assert.Equal(t, tt.want, result)
		})
	}
}
