package vex_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
)

var (
	opensslComponent = core.Component{
		Name:    "openssl",
		Version: "1.1.1t-r0",
		PkgIdentifier: ftypes.PkgIdentifier{
			UID: "01",
			PURL: &packageurl.PackageURL{
				Type:      "deb",
				Namespace: "debian",
				Name:      "openssl",
				Version:   "1.1.1t-r0",
			},
		},
	}
	opensslVuln1 = types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2023-1234",
		PkgName:          opensslComponent.Name,
		InstalledVersion: opensslComponent.Version,
		FixedVersion:     "1.1.1u-r0",
		PkgIdentifier:    opensslComponent.PkgIdentifier,
	}
	opensslVuln2 = types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2023-12345",
		PkgName:          opensslComponent.Name,
		InstalledVersion: opensslComponent.Version,
		FixedVersion:     "1.1.1u-r2",
		PkgIdentifier:    opensslComponent.PkgIdentifier,
	}
)

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
`,
			vuln:    opensslVuln1,
			product: opensslComponent,
			wantModified: types.ModifiedFinding{
				Type:      types.FindingTypeVulnerability,
				Finding:   opensslVuln1,
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
  - name: default
    url: https://example.com/vex/default`,
			vuln:            opensslVuln1,
			product:         opensslComponent,
			wantNotAffected: false,
		},
		{
			name:     "no matching VEX data",
			cacheDir: "testdata/single-repo",
			configContent: `
repositories:
  - name: default
    url: https://example.com/vex/default
`,
			vuln:            opensslVuln2,
			product:         opensslComponent,
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
			err := os.MkdirAll(vexDir, 0755)
			require.NoError(t, err)

			// Write the config file
			configPath := filepath.Join(vexDir, "repository.yaml")
			err = os.WriteFile(configPath, []byte(tt.configContent), 0644)
			require.NoError(t, err)

			ctx := context.Background()
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
