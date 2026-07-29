package chainguardosv_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/chainguardosv"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

var source = &dbTypes.DataSource{
	ID:   vulnerability.Chainguard,
	Name: "Chainguard Security Data",
	URL:  "https://advisories.cgr.dev/chainguard/v3/osv/all.json",
}

// fakeVulnSrc serves advisories from a map and records the parameters it was
// called with, so the tests can assert how the scanner queries the database.
type fakeVulnSrc struct {
	advisories map[string][]dbTypes.Advisory
	err        error
	calls      []db.GetParams
}

func (f *fakeVulnSrc) Get(params db.GetParams) ([]dbTypes.Advisory, error) {
	f.calls = append(f.calls, params)
	if f.err != nil {
		return nil, f.err
	}

	// The real data source returns the advisories for every architecture and
	// leaves the choice between them to the scanner.
	var advisories []dbTypes.Advisory
	for _, adv := range f.advisories[params.PkgName] {
		adv.DataSource = source
		advisories = append(advisories, adv)
	}
	return advisories, nil
}

func TestScanner_Detect(t *testing.T) {
	tests := []struct {
		name       string
		advisories map[string][]dbTypes.Advisory
		pkgs       []ftypes.Package
		want       []types.DetectedVulnerability
		wantCalls  []db.GetParams
	}{
		{
			name: "an outdated package is vulnerable",
			advisories: map[string][]dbTypes.Advisory{
				"glibc": {
					{
						VulnerabilityID: "CVE-2023-4911",
						FixedVersion:    "2.38-r5",
						Arches:          []string{"x86_64"},
						VendorIDs:       []string{"CGA-2222-2222-2222"},
					},
				},
			},
			pkgs: []ftypes.Package{
				{
					Name:       "glibc",
					Version:    "2.38",
					Release:    "r4",
					SrcName:    "glibc",
					SrcVersion: "2.38",
					SrcRelease: "r4",
					Arch:       "x86_64",
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
			},
			wantCalls: []db.GetParams{{PkgName: "glibc"}},
		},
		{
			name: "a package at the fixed version is not vulnerable",
			advisories: map[string][]dbTypes.Advisory{
				"glibc": {
					{
						VulnerabilityID: "CVE-2023-4911",
						FixedVersion:    "2.38-r5",
					},
				},
			},
			pkgs: []ftypes.Package{
				{
					Name:       "glibc",
					Version:    "2.38",
					Release:    "r5",
					SrcName:    "glibc",
					SrcVersion: "2.38",
					SrcRelease: "r5",
				},
			},
			want: nil,
		},
		{
			name: "an unresolved advisory makes every version vulnerable",
			advisories: map[string][]dbTypes.Advisory{
				"ko": {
					{
						VulnerabilityID: "CVE-2026-56852",
						Status:          dbTypes.StatusAffected,
						VendorIDs:       []string{"CGA-hq7p-pjjx-f394"},
					},
				},
			},
			pkgs: []ftypes.Package{
				{
					Name:       "ko",
					Version:    "0.18.0",
					Release:    "r7",
					SrcName:    "ko",
					SrcVersion: "0.18.0",
					SrcRelease: "r7",
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2026-56852",
					VendorIDs:        []string{"CGA-hq7p-pjjx-f394"},
					PkgName:          "ko",
					InstalledVersion: "0.18.0-r7",
					Status:           dbTypes.StatusAffected,
					DataSource:       source,
				},
			},
		},
		{
			// Both architectures were fixed, but in different revisions of the
			// package, so only the one built for this architecture counts.
			name: "the advisory for the package's architecture wins",
			advisories: map[string][]dbTypes.Advisory{
				"prism": {
					{
						VulnerabilityID: "CVE-2025-25289",
						FixedVersion:    "5.14.3-r8",
						Arches:          []string{"x86_64"},
					},
					{
						VulnerabilityID: "CVE-2025-25289",
						FixedVersion:    "5.14.3-r1",
						Arches:          []string{"aarch64"},
					},
				},
			},
			pkgs: []ftypes.Package{
				{
					Name:       "prism",
					Version:    "5.14.3",
					Release:    "r4",
					SrcName:    "prism",
					SrcVersion: "5.14.3",
					SrcRelease: "r4",
					Arch:       "aarch64",
				},
			},
			// The aarch64 build was fixed in r1, so r4 is not vulnerable, even
			// though the x86_64 build was not fixed until r8.
			want:      nil,
			wantCalls: []db.GetParams{{PkgName: "prism"}},
		},
		{
			// The feed covers only one architecture for around one in eleven
			// package/vulnerability pairs. Dropping those would hide the
			// vulnerability from the other architecture entirely.
			name: "an advisory recorded for one architecture applies to the other",
			advisories: map[string][]dbTypes.Advisory{
				"apache-nifi": {
					{
						VulnerabilityID: "CVE-2026-33557",
						FixedVersion:    "2.8.0-r7",
						Arches:          []string{"aarch64"},
					},
				},
			},
			pkgs: []ftypes.Package{
				{
					Name:       "apache-nifi",
					Version:    "1.27.0",
					Release:    "r0",
					SrcName:    "apache-nifi",
					SrcVersion: "1.27.0",
					SrcRelease: "r0",
					Arch:       "x86_64",
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2026-33557",
					PkgName:          "apache-nifi",
					InstalledVersion: "1.27.0-r0",
					FixedVersion:     "2.8.0-r7",
					DataSource:       source,
				},
			},
		},
		{
			name: "an architecture independent package matches every advisory",
			advisories: map[string][]dbTypes.Advisory{
				"ca-certificates": {
					{
						VulnerabilityID: "CVE-2026-22222",
						FixedVersion:    "20260101-r0",
						Arches:          []string{"x86_64"},
					},
				},
			},
			pkgs: []ftypes.Package{
				{
					Name:       "ca-certificates",
					Version:    "20251001",
					Release:    "r0",
					SrcName:    "ca-certificates",
					SrcVersion: "20251001",
					SrcRelease: "r0",
					Arch:       "noarch",
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2026-22222",
					PkgName:          "ca-certificates",
					InstalledVersion: "20251001-r0",
					FixedVersion:     "20260101-r0",
					DataSource:       source,
				},
			},
			wantCalls: []db.GetParams{{PkgName: "ca-certificates"}},
		},
		{
			// A subpackage is built from its origin and carries its origin's
			// version numbers, so advisories filed against either name apply.
			// Both are needed: matching only the origin loses the advisories the
			// subpackage carries alone, and matching only the subpackage produces
			// 40 false negatives on Chainguard's subpackage test image.
			name: "a subpackage is matched under its own name and its origin's",
			advisories: map[string][]dbTypes.Advisory{
				"libcrypto3": {
					{
						VulnerabilityID: "CVE-2026-11111",
						FixedVersion:    "3.6.0-r0",
					},
				},
				"openssl": {
					{
						VulnerabilityID: "CVE-2024-9143",
						FixedVersion:    "3.3.3-r0",
					},
				},
			},
			pkgs: []ftypes.Package{
				{
					Name:       "libcrypto3",
					Version:    "3.3.2",
					Release:    "r0",
					SrcName:    "openssl",
					SrcVersion: "3.3.2",
					SrcRelease: "r0",
				},
			},
			want: []types.DetectedVulnerability{
				{
					// Filed against the origin package openssl.
					VulnerabilityID:  "CVE-2024-9143",
					PkgName:          "libcrypto3",
					InstalledVersion: "3.3.2-r0",
					FixedVersion:     "3.3.3-r0",
					DataSource:       source,
				},
				{
					// Filed against the subpackage libcrypto3.
					VulnerabilityID:  "CVE-2026-11111",
					PkgName:          "libcrypto3",
					InstalledVersion: "3.3.2-r0",
					FixedVersion:     "3.6.0-r0",
					DataSource:       source,
				},
			},
			wantCalls: []db.GetParams{
				{PkgName: "libcrypto3"},
				{PkgName: "openssl"},
			},
		},
		{
			// Both names carry the same vulnerability but name different fixed
			// versions. The package is only safe once it reaches the later one,
			// otherwise it would be reported as fixed while a component covered
			// by the other advisory is still vulnerable.
			name: "the later fixed version wins across the two names",
			advisories: map[string][]dbTypes.Advisory{
				"katib-suggestion-skopt-enas": {
					{
						VulnerabilityID: "CVE-2021-4231",
						FixedVersion:    "0.19.0-r31",
					},
				},
				"kubeflow-katib": {
					{
						VulnerabilityID: "CVE-2021-4231",
						FixedVersion:    "0.17.0-r13",
					},
				},
			},
			pkgs: []ftypes.Package{
				{
					Name:       "katib-suggestion-skopt-enas",
					Version:    "0.18.0",
					Release:    "r0",
					SrcName:    "kubeflow-katib",
					SrcVersion: "0.18.0",
					SrcRelease: "r0",
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2021-4231",
					PkgName:          "katib-suggestion-skopt-enas",
					InstalledVersion: "0.18.0-r0",
					FixedVersion:     "0.19.0-r31",
					DataSource:       source,
				},
			},
		},
		{
			name: "a package with no origin is matched against its own name",
			advisories: map[string][]dbTypes.Advisory{
				"jq": {
					{
						VulnerabilityID: "CVE-2020-1234",
						FixedVersion:    "1.6-r1",
					},
				},
			},
			pkgs: []ftypes.Package{
				{
					Name:    "jq",
					Version: "1.6",
					Release: "r0",
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2020-1234",
					PkgName:          "jq",
					InstalledVersion: "1.6-r0",
					FixedVersion:     "1.6-r1",
					DataSource:       source,
				},
			},
			wantCalls: []db.GetParams{{PkgName: "jq"}},
		},
		{
			name: "unresolved beats fixed when both apply to a package",
			advisories: map[string][]dbTypes.Advisory{
				"openssl": {
					{
						VulnerabilityID: "CVE-2026-33333",
						FixedVersion:    "3.6.2-r0",
						Arches:          []string{"x86_64"},
					},
					{
						VulnerabilityID: "CVE-2026-33333",
						Status:          dbTypes.StatusFixDeferred,
						Arches:          []string{"aarch64"},
					},
				},
			},
			pkgs: []ftypes.Package{
				{
					// No architecture, so both advisories are returned and the
					// scanner has to choose between them.
					Name:       "openssl",
					Version:    "3.6.2",
					Release:    "r0",
					SrcName:    "openssl",
					SrcVersion: "3.6.2",
					SrcRelease: "r0",
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2026-33333",
					PkgName:          "openssl",
					InstalledVersion: "3.6.2-r0",
					Status:           dbTypes.StatusFixDeferred,
					DataSource:       source,
				},
			},
		},
		{
			name: "the highest fixed version wins when both apply to a package",
			advisories: map[string][]dbTypes.Advisory{
				"busybox": {
					{
						VulnerabilityID: "CVE-2024-58251",
						FixedVersion:    "1.37.0-r9",
						Arches:          []string{"x86_64"},
					},
					{
						VulnerabilityID: "CVE-2024-58251",
						FixedVersion:    "1.37.0-r49",
						Arches:          []string{"aarch64"},
					},
				},
			},
			pkgs: []ftypes.Package{
				{
					Name:       "busybox",
					Version:    "1.37.0",
					Release:    "r12",
					SrcName:    "busybox",
					SrcVersion: "1.37.0",
					SrcRelease: "r12",
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2024-58251",
					PkgName:          "busybox",
					InstalledVersion: "1.37.0-r12",
					FixedVersion:     "1.37.0-r49",
					DataSource:       source,
				},
			},
		},
		{
			// Both apply to this package and neither has a fix, so the status a
			// user most needs to act on is the one reported.
			name: "the most pressing unresolved status is reported",
			advisories: map[string][]dbTypes.Advisory{
				"haproxy-2.2": {
					{
						VulnerabilityID: "CVE-2025-32464",
						Status:          dbTypes.StatusUnderInvestigation,
						Arches:          []string{"x86_64"},
						VendorIDs:       []string{"CGA-detect-0000-00"},
					},
					{
						VulnerabilityID: "CVE-2025-32464",
						Status:          dbTypes.StatusFixDeferred,
						Arches:          []string{"aarch64"},
						VendorIDs:       []string{"CGA-pending-000-00"},
					},
				},
			},
			pkgs: []ftypes.Package{
				{
					// No architecture, so both advisories are candidates.
					Name:       "haproxy-2.2",
					Version:    "2.2.33",
					Release:    "r40",
					SrcName:    "haproxy-2.2",
					SrcVersion: "2.2.33",
					SrcRelease: "r40",
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2025-32464",
					VendorIDs:        []string{"CGA-pending-000-00"},
					PkgName:          "haproxy-2.2",
					InstalledVersion: "2.2.33-r40",
					Status:           dbTypes.StatusFixDeferred,
					DataSource:       source,
				},
			},
		},
		{
			name: "an unparsable installed version is skipped",
			advisories: map[string][]dbTypes.Advisory{
				"invalid": {
					{
						VulnerabilityID: "CVE-2026-44444",
						FixedVersion:    "1.0.0-r0",
					},
				},
			},
			pkgs: []ftypes.Package{
				{
					Name:    "invalid",
					Version: "invalid",
					SrcName: "invalid",
				},
			},
			want: nil,
		},
		{
			name: "an unparsable fixed version is skipped",
			advisories: map[string][]dbTypes.Advisory{
				"broken": {
					{
						VulnerabilityID: "CVE-2026-55555",
						FixedVersion:    "invalid",
					},
				},
			},
			pkgs: []ftypes.Package{
				{
					Name:    "broken",
					Version: "1.0.0",
					Release: "r0",
					SrcName: "broken",
				},
			},
			want: nil,
		},
		{
			name:       "a package with no advisories is not queried twice",
			advisories: map[string][]dbTypes.Advisory{},
			pkgs: []ftypes.Package{
				{
					Name:    "unknown",
					Version: "1.0.0",
					Release: "r0",
					SrcName: "unknown",
				},
			},
			want:      nil,
			wantCalls: []db.GetParams{{PkgName: "unknown"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := &fakeVulnSrc{advisories: tt.advisories}
			s := chainguardosv.NewScanner(vs, "Chainguard")

			got, err := s.Detect(t.Context(), "", nil, tt.pkgs)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			if tt.wantCalls != nil {
				assert.Equal(t, tt.wantCalls, vs.calls)
			}
		})
	}
}

func TestScanner_Detect_error(t *testing.T) {
	vs := &fakeVulnSrc{err: assert.AnError}
	s := chainguardosv.NewScanner(vs, "Chainguard")

	_, err := s.Detect(t.Context(), "", nil, []ftypes.Package{
		{
			Name:    "jq",
			Version: "1.6",
			Release: "r0",
			SrcName: "jq",
		},
	})
	require.ErrorContains(t, err, "failed to get Chainguard advisories")
}

func TestScanner_IsSupportedVersion(t *testing.T) {
	s := chainguardosv.NewScanner(&fakeVulnSrc{}, "Chainguard")

	// Neither distro is versioned, so every input is supported.
	assert.True(t, s.IsSupportedVersion(t.Context(), ftypes.Chainguard, ""))
	assert.True(t, s.IsSupportedVersion(t.Context(), ftypes.Chainguard, "20230214"))
	assert.True(t, s.IsSupportedVersion(t.Context(), ftypes.Wolfi, "20230201"))
}
