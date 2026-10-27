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

// TestRepositorySet_NotAffected_readsEachDocumentOnce checks that a package's VEX document is opened
// once, not once per vulnerability: the document file is removed or restored after the first check,
// and the next checks must still return the result of the first one.
func TestRepositorySet_NotAffected_readsEachDocumentOnce(t *testing.T) {
	tests := []struct {
		name string
		// docExists is whether the document exists for the first check; the next checks see the opposite.
		docExists       bool
		wantModified    types.ModifiedFinding
		wantNotAffected bool
	}{
		{
			name:      "opened document is reused after the file is removed",
			docExists: true,
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
			name:            "open error is reused after the file is restored",
			docExists:       false,
			wantNotAffected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Work on a copy so the document can be removed and restored.
			cacheDir := t.TempDir()
			require.NoError(t, os.CopyFS(cacheDir, os.DirFS("testdata/single-repo")))
			docPath := filepath.Join(cacheDir, "vex", "repositories", "default", "0.1", "bash-vex.json")
			doc, err := os.ReadFile(docPath)
			require.NoError(t, err)
			if !tt.docExists {
				require.NoError(t, os.Remove(docPath))
			}

			dataHome := t.TempDir()
			t.Setenv("XDG_DATA_HOME", dataHome)
			vexDir := filepath.Join(dataHome, ".trivy", "vex")
			require.NoError(t, os.MkdirAll(vexDir, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(vexDir, "repository.yaml"), []byte(`
repositories:
  - name: default
    url: https://example.com/vex/default
    enabled: true
`), 0o644))

			rs, err := vex.NewRepositorySet(t.Context(), cacheDir)
			require.NoError(t, err)

			for i := range 3 {
				if i == 1 {
					// Flip the document after the first check; a cached result must not notice.
					if tt.docExists {
						require.NoError(t, os.Remove(docPath))
					} else {
						require.NoError(t, os.WriteFile(docPath, doc, 0o644))
					}
				}

				modified, notAffected := rs.NotAffected(vuln3, &bashComponent, nil)
				assert.Equal(t, tt.wantNotAffected, notAffected)
				assert.Equal(t, tt.wantModified, modified)
			}
		})
	}
}
