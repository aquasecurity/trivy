package rootio_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/library/rootio"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Detect(t *testing.T) {
	tests := []struct {
		name      string
		fixtures  []string
		ecosystem ecosystem.Type
		pkg       ftypes.Package
		wantVulns []types.DetectedVulnerability
	}{
		{
			name: "Root.io pip package with Root.io and GitHub vulns",
			fixtures: []string{
				"testdata/fixtures/pip.yaml",
				"testdata/fixtures/rootio.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			ecosystem: ecosystem.Pip,
			pkg: ftypes.Package{
				Name:       "django",
				Version:    "4.0.1+root.io.1",
				Layer:      ftypes.Layer{Digest: "sha256:layer"},
				FilePath:   "/path/to/requirements.txt",
				Identifier: ftypes.PkgIdentifier{UID: "01"},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					// Vulnerability from GitHub Security Advisory Pip
					VulnerabilityID:  "CVE-2022-1234",
					PkgName:          "django",
					InstalledVersion: "4.0.1+root.io.1",
					FixedVersion:     "4.0.2",
					Layer:            ftypes.Layer{Digest: "sha256:layer"},
					PkgPath:          "/path/to/requirements.txt",
					PkgIdentifier:    ftypes.PkgIdentifier{UID: "01"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Pip",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip",
					},
				},
				{
					// Vulnerability from Root.io pip
					VulnerabilityID:  "CVE-2022-5678",
					PkgName:          "django",
					InstalledVersion: "4.0.1+root.io.1",
					FixedVersion:     "4.0.1+root.io.2",
					Layer:            ftypes.Layer{Digest: "sha256:layer"},
					PkgPath:          "/path/to/requirements.txt",
					PkgIdentifier:    ftypes.PkgIdentifier{UID: "01"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.RootIO,
						Name: "root.io pip",
						URL:  "https://api.root.io/external/patch_feed",
					},
				},
				{
					// GitHub Security Advisory Pip and Root.io pip have the same CVE
					// Use  Root.io pip
					VulnerabilityID:  "CVE-2023-1234",
					PkgName:          "django",
					InstalledVersion: "4.0.1+root.io.1",
					FixedVersion:     "4.0.1+root.io.2",
					Layer:            ftypes.Layer{Digest: "sha256:layer"},
					PkgPath:          "/path/to/requirements.txt",
					PkgIdentifier:    ftypes.PkgIdentifier{UID: "01"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.RootIO,
						Name: "root.io pip",
						URL:  "https://api.root.io/external/patch_feed",
					},
				},
			},
		},
		{
			name: "pip package with Root.io vulns",
			fixtures: []string{
				"testdata/fixtures/pip.yaml",
				"testdata/fixtures/rootio.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			ecosystem: ecosystem.Pip,
			pkg: ftypes.Package{
				Name:       "requests",
				Version:    "2.30.0",
				Layer:      ftypes.Layer{Digest: "sha256:layer"},
				FilePath:   "/path/to/requirements.txt",
				Identifier: ftypes.PkgIdentifier{UID: "01"},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2023-32681",
					PkgName:          "requests",
					InstalledVersion: "2.30.0",
					FixedVersion:     "2.30.0+root.io.3",
					Layer:            ftypes.Layer{Digest: "sha256:layer"},
					PkgPath:          "/path/to/requirements.txt",
					PkgIdentifier:    ftypes.PkgIdentifier{UID: "01"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.RootIO,
						Name: "root.io pip",
						URL:  "https://api.root.io/external/patch_feed",
					},
				},
			},
		},
		{
			name: "Root.io npm package with Root.io and GitHub vulns",
			fixtures: []string{
				//"testdata/fixtures/npm.yaml",
				"testdata/fixtures/rootio.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			ecosystem: ecosystem.Npm,
			pkg: ftypes.Package{
				Name:       "lodash",
				Version:    "4.17.20+root.io.1",
				Layer:      ftypes.Layer{Digest: "sha256:layer"},
				FilePath:   "/path/to/package.json",
				Identifier: ftypes.PkgIdentifier{UID: "01"},
			},
			wantVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2020-28500",
					PkgName:          "lodash",
					InstalledVersion: "4.17.20+root.io.1",
					FixedVersion:     "4.17.21",
					Layer:            ftypes.Layer{Digest: "sha256:layer"},
					PkgPath:          "/path/to/package.json",
					PkgIdentifier:    ftypes.PkgIdentifier{UID: "01"},
					DataSource: &dbTypes.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory npm",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm",
					},
				},
			},
		},
		{
			name: "Package with no vulnerabilities",
			fixtures: []string{
				"testdata/fixtures/pip.yaml",
				"testdata/fixtures/rootio.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			ecosystem: ecosystem.Pip,
			pkg: ftypes.Package{
				Name:       "requests",
				Version:    "2.28.1+root.io.1",
				Layer:      ftypes.Layer{Digest: "sha256:layer"},
				FilePath:   "/path/to/requirements.txt",
				Identifier: ftypes.PkgIdentifier{UID: "01"},
			},
			wantVulns: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			driver := rootio.NewScanner(tt.ecosystem)
			vulns, err := driver.Detect(t.Context(), tt.pkg)
			require.NoError(t, err)

			assert.Equal(t, tt.wantVulns, vulns)
		})
	}
}
