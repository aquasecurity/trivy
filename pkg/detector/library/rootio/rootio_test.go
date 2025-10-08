package rootio

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
	"github.com/aquasecurity/trivy/pkg/types"
)

// mockDBConfig is a mock implementation of db.Config
type mockDBConfig struct {
	advisories []dbTypes.Advisory
	err        error
}

func (m *mockDBConfig) GetAdvisories(prefix, pkgName string) ([]dbTypes.Advisory, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.advisories, nil
}

func TestScanner_DetectVulnerabilities(t *testing.T) {
	tests := []struct {
		name       string
		ecosystem  ecosystem.Type
		pkgID      string
		pkgName    string
		pkgVer     string
		advisories []dbTypes.Advisory
		wantVulns  []types.DetectedVulnerability
	}{
		{
			name:      "Root.io package with standard advisory",
			ecosystem: ecosystem.Pip,
			pkgID:     "django@4.0.1+root.io.1",
			pkgName:   "django",
			pkgVer:    "4.0.1+root.io.1",
			advisories: []dbTypes.Advisory{
				{
					VulnerabilityID:    "CVE-2022-1234",
					VulnerableVersions: []string{"<4.0.2"},
					PatchedVersions:    []string{"4.0.2"},  // Standard advisory with standard version
					DataSource: &dbTypes.DataSource{
						ID:   "ghsa",
						Name: "GitHub Security Advisory",
					},
				},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2022-1234",
					PkgID:            "django@4.0.1+root.io.1",
					PkgName:          "django",
					InstalledVersion: "4.0.1+root.io.1",
					FixedVersion:     "4.0.2",  // Uses version as-is from advisory
					DataSource: &dbTypes.DataSource{
						ID:   "ghsa",
						Name: "GitHub Security Advisory",
					},
				},
			},
		},
		{
			name:      "Root.io package with Root.io advisory",
			ecosystem: ecosystem.Pip,
			pkgID:     "django@4.0.1+root.io.1",
			pkgName:   "django",
			pkgVer:    "4.0.1+root.io.1",
			advisories: []dbTypes.Advisory{
				{
					VulnerabilityID:    "CVE-2022-5678",
					VulnerableVersions: []string{"<4.0.3"},
					PatchedVersions:    []string{"4.0.3+root.io.1"},  // Root.io advisory has +root.io suffix
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.RootIO,
						Name: "Root.io Security Patches",
					},
				},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2022-5678",
					PkgID:            "django@4.0.1+root.io.1",
					PkgName:          "django",
					InstalledVersion: "4.0.1+root.io.1",
					FixedVersion:     "4.0.3+root.io.1",  // Uses version as-is from Root.io advisory
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.RootIO,
						Name: "Root.io Security Patches",
					},
				},
			},
		},
		{
			name:      "Standard package with standard advisory",
			ecosystem: ecosystem.Pip,
			pkgID:     "django@4.0.1",
			pkgName:   "django",
			pkgVer:    "4.0.1",
			advisories: []dbTypes.Advisory{
				{
					VulnerabilityID:    "CVE-2022-1234",
					VulnerableVersions: []string{"<4.0.2"},
					PatchedVersions:    []string{"4.0.2"},
					DataSource: &dbTypes.DataSource{
						ID:   "ghsa",
						Name: "GitHub Security Advisory",
					},
				},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2022-1234",
					PkgID:            "django@4.0.1",
					PkgName:          "django",
					InstalledVersion: "4.0.1",
					FixedVersion:     "4.0.2",
					DataSource: &dbTypes.DataSource{
						ID:   "ghsa",
						Name: "GitHub Security Advisory",
					},
				},
			},
		},
		{
			name:      "Package with no vulnerabilities",
			ecosystem: ecosystem.Pip,
			pkgID:     "requests@2.28.1+root.io.1",
			pkgName:   "requests",
			pkgVer:    "2.28.1+root.io.1",
			advisories: []dbTypes.Advisory{
				{
					VulnerabilityID:    "CVE-2022-5678",
					VulnerableVersions: []string{"<2.28.0"},
					PatchedVersions:    []string{"2.28.0"},
				},
			},
			wantVulns: nil,
		},
		{
			name:       "Package with no advisories",
			ecosystem:  ecosystem.Pip,
			pkgID:      "safe-package@1.0.0+root.io.1",
			pkgName:    "safe-package",
			pkgVer:     "1.0.0+root.io.1",
			advisories: []dbTypes.Advisory{},
			wantVulns:  nil,
		},
		{
			name:      "Root.io package with multiple standard vulnerabilities",
			ecosystem: ecosystem.Npm,
			pkgID:     "lodash@4.17.20+root.io.1",
			pkgName:   "lodash",
			pkgVer:    "4.17.20+root.io.1",
			advisories: []dbTypes.Advisory{
				{
					VulnerabilityID:    "CVE-2021-1111",
					VulnerableVersions: []string{"<4.17.21"},
					PatchedVersions:    []string{"4.17.21"},
					DataSource: &dbTypes.DataSource{
						ID: "npm",
					},
				},
				{
					VulnerabilityID:    "CVE-2021-2222",
					VulnerableVersions: []string{"<=4.17.20"},
					PatchedVersions:    []string{"4.17.21"},
					DataSource: &dbTypes.DataSource{
						ID: "npm",
					},
				},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2021-1111",
					PkgID:            "lodash@4.17.20+root.io.1",
					PkgName:          "lodash",
					InstalledVersion: "4.17.20+root.io.1",
					FixedVersion:     "4.17.21",  // Standard advisories use standard versions
					DataSource: &dbTypes.DataSource{
						ID: "npm",
					},
				},
				{
					VulnerabilityID:  "CVE-2021-2222",
					PkgID:            "lodash@4.17.20+root.io.1",
					PkgName:          "lodash",
					InstalledVersion: "4.17.20+root.io.1",
					FixedVersion:     "4.17.21",  // Standard advisories use standard versions
					DataSource: &dbTypes.DataSource{
						ID: "npm",
					},
				},
			},
		},
		{
			name:      "Mixed advisories - Root.io and standard",
			ecosystem: ecosystem.Npm,
			pkgID:     "express@4.17.0+root.io.1",
			pkgName:   "express",
			pkgVer:    "4.17.0+root.io.1",
			advisories: []dbTypes.Advisory{
				{
					VulnerabilityID:    "CVE-2021-3333",
					VulnerableVersions: []string{"<4.17.2"},
					PatchedVersions:    []string{"4.17.2"},  // Standard advisory
					DataSource: &dbTypes.DataSource{
						ID: "npm",
					},
				},
				{
					VulnerabilityID:    "CVE-2021-4444",
					VulnerableVersions: []string{"<4.17.1"},
					PatchedVersions:    []string{"4.17.1+root.io.1"},  // Root.io advisory with +root.io suffix
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.RootIO,
						Name: "Root.io Security Patches",
					},
				},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2021-3333",
					PkgID:            "express@4.17.0+root.io.1",
					PkgName:          "express",
					InstalledVersion: "4.17.0+root.io.1",
					FixedVersion:     "4.17.2",  // Standard advisory uses standard version
					DataSource: &dbTypes.DataSource{
						ID: "npm",
					},
				},
				{
					VulnerabilityID:  "CVE-2021-4444",
					PkgID:            "express@4.17.0+root.io.1",
					PkgName:          "express",
					InstalledVersion: "4.17.0+root.io.1",
					FixedVersion:     "4.17.1+root.io.1",  // Root.io advisory uses +root.io version
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.RootIO,
						Name: "Root.io Security Patches",
					},
				},
			},
		},
		{
			name:      "Advisory with no patched versions",
			ecosystem: ecosystem.Pip,
			pkgID:     "requests@2.25.0+root.io.1",
			pkgName:   "requests",
			pkgVer:    "2.25.0+root.io.1",
			advisories: []dbTypes.Advisory{
				{
					VulnerabilityID:    "CVE-2023-9999",
					VulnerableVersions: []string{">=2.0.0, <2.26.0"},
					PatchedVersions:    []string{},  // No patched versions
					DataSource: &dbTypes.DataSource{
						ID: "osv",
					},
				},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2023-9999",
					PkgID:            "requests@2.25.0+root.io.1",
					PkgName:          "requests",
					InstalledVersion: "2.25.0+root.io.1",
					FixedVersion:     "",  // No fixed version when PatchedVersions is empty
					DataSource: &dbTypes.DataSource{
						ID: "osv",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create scanner with mock
			scanner := &Scanner{
				ecosystem: tt.ecosystem,
				comparer:  getComparerForEcosystem(tt.ecosystem),
				dbc:       &mockDBConfig{advisories: tt.advisories},
			}

			gotVulns, err := scanner.DetectVulnerabilities(tt.pkgID, tt.pkgName, tt.pkgVer)
			require.NoError(t, err)
			assert.Equal(t, tt.wantVulns, gotVulns)
		})
	}
}

func TestGetComparerForEcosystem(t *testing.T) {
	tests := []struct {
		name         string
		ecosystem    ecosystem.Type
		wantComparer compare.Comparer
	}{
		{
			name:         "Python Pip uses PEP440",
			ecosystem:    ecosystem.Pip,
			wantComparer: pep440.Comparer{},
		},
		{
			name:         "Generic ecosystem uses GenericComparer",
			ecosystem:    ecosystem.Go,
			wantComparer: compare.GenericComparer{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comparer := getComparerForEcosystem(tt.ecosystem)
			assert.IsType(t, tt.wantComparer, comparer)
		})
	}
}

func TestScanner_Type(t *testing.T) {
	scanner := NewScanner(ecosystem.Pip, pep440.Comparer{})
	assert.Equal(t, "pip", scanner.Type())

	scanner2 := NewScanner(ecosystem.Npm, compare.GenericComparer{})
	assert.Equal(t, "npm", scanner2.Type())
}
