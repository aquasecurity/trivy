package vex_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
)

var bashComponent = core.Component{
	Name:          bashPackage.Name,
	Version:       bashPackage.Version,
	PkgIdentifier: bashPackage.Identifier,
}

func TestRepositorySet_NotAffected(t *testing.T) {
	tests := []struct {
		name            string
		cacheDir        string
		configContent   string
		vuln            types.DetectedVulnerability
		product         core.Component
		wantModified    types.ModifiedFinding
		wantNotAffected bool
	}{
		{
			name:     "single repository - not affected",
			cacheDir: "testdata/single-repo",
			configContent: `
repositories:
  - name: default
    url: https://example.com/vex/default
    enabled: true
`,
			vuln:    vuln3,
			product: bashComponent,
			wantModified: types.ModifiedFinding{
				Type:      types.FindingTypeVulnerability,
				Finding:   vuln3,
				Status:    types.FindingStatusNotAffected,
				Statement: "vulnerable_code_not_in_execute_path",
				Source:    "VEX Repository: default (https://example.com/vex/default)",
			},
			wantNotAffected: true,
		},
		{
			name:     "multiple repositories - high priority affected",
			cacheDir: "testdata/multi-repos",
			configContent: `
repositories:
  - name: high-priority
    url: https://example.com/vex/high-priority
    enabled: true
  - name: default
    url: https://example.com/vex/default
    enabled: true
`,
			vuln:            vuln3,
			product:         bashComponent,
			wantNotAffected: false,
		},
		{
			// The higher-priority repository indexes the package, but its document has no
			// statement about this vulnerability. An index entry only tells Trivy which
			// document covers the package, so the repository expressed no opinion here and
			// the lower-priority repository must still be consulted.
			name:     "multiple repositories - high priority has no statement",
			cacheDir: "testdata/multi-repos-no-statement",
			configContent: `
repositories:
  - name: high-priority
    url: https://example.com/vex/high-priority
    enabled: true
  - name: default
    url: https://example.com/vex/default
    enabled: true
`,
			vuln:    vuln3,
			product: bashComponent,
			wantModified: types.ModifiedFinding{
				Type:      types.FindingTypeVulnerability,
				Finding:   vuln3,
				Status:    types.FindingStatusNotAffected,
				Statement: "vulnerable_code_not_in_execute_path",
				Source:    "VEX Repository: default (https://example.com/vex/default)",
			},
			wantNotAffected: true,
		},
		{
			// The higher-priority repository states "not_affected", so it wins and the
			// lower-priority repository, which states "affected", is never consulted.
			name:     "multiple repositories - high priority not affected",
			cacheDir: "testdata/multi-repos",
			configContent: `
repositories:
  - name: default
    url: https://example.com/vex/default
    enabled: true
  - name: high-priority
    url: https://example.com/vex/high-priority
    enabled: true
`,
			vuln:    vuln3,
			product: bashComponent,
			wantModified: types.ModifiedFinding{
				Type:      types.FindingTypeVulnerability,
				Finding:   vuln3,
				Status:    types.FindingStatusNotAffected,
				Statement: "vulnerable_code_not_in_execute_path",
				Source:    "VEX Repository: default (https://example.com/vex/default)",
			},
			wantNotAffected: true,
		},
		{
			// "under_investigation" is a statement, not silence. The higher-priority
			// repository is engaged with the vulnerability, so the lower-priority
			// "not_affected" must not suppress the finding.
			name:     "multiple repositories - high priority under investigation",
			cacheDir: "testdata/multi-repos-no-statement",
			configContent: `
repositories:
  - name: under-investigation
    url: https://example.com/vex/under-investigation
    enabled: true
  - name: default
    url: https://example.com/vex/default
    enabled: true
`,
			vuln:            vuln3,
			product:         bashComponent,
			wantNotAffected: false,
		},
		{
			// The higher-priority repository doesn't index the package at all.
			name:     "multiple repositories - package only in the lower priority repository",
			cacheDir: "testdata/multi-repos-no-statement",
			configContent: `
repositories:
  - name: other-package
    url: https://example.com/vex/other-package
    enabled: true
  - name: default
    url: https://example.com/vex/default
    enabled: true
`,
			vuln:    vuln3,
			product: bashComponent,
			wantModified: types.ModifiedFinding{
				Type:      types.FindingTypeVulnerability,
				Finding:   vuln3,
				Status:    types.FindingStatusNotAffected,
				Statement: "vulnerable_code_not_in_execute_path",
				Source:    "VEX Repository: default (https://example.com/vex/default)",
			},
			wantNotAffected: true,
		},
		{
			name:     "multiple repositories - no statement in any repository",
			cacheDir: "testdata/multi-repos-no-statement",
			configContent: `
repositories:
  - name: high-priority
    url: https://example.com/vex/high-priority
    enabled: true
  - name: other-package
    url: https://example.com/vex/other-package
    enabled: true
`,
			vuln:            vuln3,
			product:         bashComponent,
			wantNotAffected: false,
		},
		{
			name:     "no matching VEX data",
			cacheDir: "testdata/single-repo",
			configContent: `
repositories:
  - name: default
    url: https://example.com/vex/default
    enabled: true
`,
			vuln:            vuln4,
			product:         bashComponent,
			wantNotAffected: false,
		},
		{
			// The index entry's location ("../bash-vex.json") points to a file in
			// the parent of the repository directory. VEX documents are only loaded
			// from within the repository directory, so the document is not loaded
			// and the finding is returned unmodified (not affected = false), even
			// though that file marks it as not_affected.
			name:     "entry location in a parent directory is not loaded",
			cacheDir: "testdata/parent-location-repo",
			configContent: `
repositories:
  - name: default
    url: https://example.com/vex/default
    enabled: true
`,
			vuln:            vuln3,
			product:         bashComponent,
			wantNotAffected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary directory for each test
			tmpDir := t.TempDir()

			// Set XDG_DATA_HOME to the temporary directory
			t.Setenv("XDG_DATA_HOME", tmpDir)

			// Create the vex directory in the temporary directory
			vexDir := filepath.Join(tmpDir, ".trivy", "vex")
			err := os.MkdirAll(vexDir, 0o755)
			require.NoError(t, err)

			// Write the config file
			configPath := filepath.Join(vexDir, "repository.yaml")
			err = os.WriteFile(configPath, []byte(tt.configContent), 0o644)
			require.NoError(t, err)

			ctx := t.Context()
			rs, err := vex.NewRepositorySet(ctx, tt.cacheDir)
			require.NoError(t, err)

			modified, notAffected := rs.NotAffected(tt.vuln, &tt.product, nil)
			assert.Equal(t, tt.wantNotAffected, notAffected)
			if tt.wantNotAffected {
				assert.Equal(t, tt.wantModified, modified)
			}
		})
	}
}
