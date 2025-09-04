package rootio

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		ecosystem  dbTypes.Ecosystem
		pkgID      string
		pkgName    string
		pkgVer     string
		advisories []dbTypes.Advisory
		wantVulns  []types.DetectedVulnerability
	}{
		{
			name:      "Python package with vulnerability",
			ecosystem: vulnerability.Pip,
			pkgID:     "django@4.0.1.root.io",
			pkgName:   "django",
			pkgVer:    "4.0.1.root.io",
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
					PkgID:            "django@4.0.1.root.io",
					PkgName:          "django",
					InstalledVersion: "4.0.1.root.io",
					FixedVersion:     "4.0.2.root.io",
					DataSource: &dbTypes.DataSource{
						ID:   "ghsa",
						Name: "GitHub Security Advisory",
					},
				},
			},
		},
		{
			name:      "Package with no vulnerabilities",
			ecosystem: vulnerability.Pip,
			pkgID:     "requests@2.28.1.root.io",
			pkgName:   "requests",
			pkgVer:    "2.28.1.root.io",
			advisories: []dbTypes.Advisory{
				{
					VulnerabilityID:    "CVE-2022-5678",
					VulnerableVersions: []string{"<2.28.0"},
					PatchedVersions:    []string{"2.28.0.root.io"},
				},
			},
			wantVulns: nil,
		},
		{
			name:       "Package with no advisories",
			ecosystem:  vulnerability.Pip,
			pkgID:      "safe-package@1.0.0.root.io",
			pkgName:    "safe-package",
			pkgVer:     "1.0.0.root.io",
			advisories: []dbTypes.Advisory{},
			wantVulns:  nil,
		},
		{
			name:      "Package with multiple vulnerabilities",
			ecosystem: vulnerability.Npm,
			pkgID:     "lodash@4.17.20.root.io",
			pkgName:   "lodash",
			pkgVer:    "4.17.20.root.io",
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
					PkgID:            "lodash@4.17.20.root.io",
					PkgName:          "lodash",
					InstalledVersion: "4.17.20.root.io",
					FixedVersion:     "4.17.21.root.io",
					DataSource: &dbTypes.DataSource{
						ID: "npm",
					},
				},
				{
					VulnerabilityID:  "CVE-2021-2222",
					PkgID:            "lodash@4.17.20.root.io",
					PkgName:          "lodash",
					InstalledVersion: "4.17.20.root.io",
					FixedVersion:     "4.17.21.root.io",
					DataSource: &dbTypes.DataSource{
						ID: "npm",
					},
				},
			},
		},
		{
			name:      "Vulnerability with version range",
			ecosystem: vulnerability.Pip,
			pkgID:     "requests@2.25.0.root.io",
			pkgName:   "requests",
			pkgVer:    "2.25.0.root.io",
			advisories: []dbTypes.Advisory{
				{
					VulnerabilityID:    "CVE-2023-9999",
					VulnerableVersions: []string{">=2.0.0, <2.26.0"},
					PatchedVersions:    []string{}, // Fix version will be extracted from VulnerableVersions
					DataSource: &dbTypes.DataSource{
						ID: "osv",
					},
				},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2023-9999",
					PkgID:            "requests@2.25.0.root.io",
					PkgName:          "requests",
					InstalledVersion: "2.25.0.root.io",
					FixedVersion:     "2.26.0.root.io",
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
		ecosystem    dbTypes.Ecosystem
		wantComparer compare.Comparer
	}{
		{
			name:         "Python Pip uses PEP440",
			ecosystem:    vulnerability.Pip,
			wantComparer: pep440.Comparer{},
		},
		{
			name:         "Generic ecosystem uses GenericComparer",
			ecosystem:    vulnerability.Go,
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
	scanner := NewScanner(vulnerability.Pip, pep440.Comparer{})
	assert.Equal(t, "pip", scanner.Type())

	scanner2 := NewScanner(vulnerability.Npm, compare.GenericComparer{})
	assert.Equal(t, "npm", scanner2.Type())
}
