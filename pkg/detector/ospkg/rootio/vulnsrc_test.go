package rootio

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

func TestNewMockVulnSrc(t *testing.T) {
	vs := newMockVulnSrc()
	require.NotNil(t, vs)
	
	// Verify it implements the VulnSrc interface
	_, ok := vs.(VulnSrc)
	assert.True(t, ok, "newMockVulnSrc should return an implementation of VulnSrc interface")
}

func TestMockVulnSrc_Get(t *testing.T) {
	tests := []struct {
		name    string
		osVer   string
		pkgName string
		want    []dbTypes.Advisory
	}{
		{
			name:    "Known test package",
			osVer:   "11",
			pkgName: "test-package",
			want: []dbTypes.Advisory{
				{
					VulnerabilityID: "CVE-2023-0001",
					FixedVersion:    ">= 1.2.0",
					AffectedVersion: "< 1.2.0",
					DataSource: &dbTypes.DataSource{
						ID:   "rootio",
						Name: "Root.io Security Advisory",
						URL:  "https://rootio.example.com/advisories",
					},
				},
			},
		},
		{
			name:    "Known package with different OS version",
			osVer:   "12",
			pkgName: "test-package",
			want:    []dbTypes.Advisory{}, // Empty slice for non-matching OS version
		},
		{
			name:    "Different package name",
			osVer:   "11",
			pkgName: "other-package",
			want:    []dbTypes.Advisory{}, // Empty slice for non-matching package
		},
		{
			name:    "Unknown package",
			osVer:   "11",
			pkgName: "unknown-package",
			want:    []dbTypes.Advisory{}, // Empty slice for unknown package
		},
		{
			name:    "Empty package name",
			osVer:   "11",
			pkgName: "",
			want:    []dbTypes.Advisory{}, // Empty slice for empty package name
		},
		{
			name:    "Empty OS version",
			osVer:   "",
			pkgName: "test-package",
			want:    []dbTypes.Advisory{}, // Empty slice for empty OS version
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := newMockVulnSrc()
			got, err := vs.Get(tt.osVer, tt.pkgName)
			
			require.NoError(t, err, "Get should not return an error")
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMockVulnSrc_GetAdvisoryFields(t *testing.T) {
	vs := newMockVulnSrc()
	advisories, err := vs.Get("11", "test-package")
	
	require.NoError(t, err)
	require.Len(t, advisories, 1, "Should return exactly one advisory for test-package")
	
	advisory := advisories[0]
	
	// Test all fields of the returned advisory
	assert.Equal(t, "CVE-2023-0001", advisory.VulnerabilityID)
	assert.Equal(t, ">= 1.2.0", advisory.FixedVersion)
	assert.Equal(t, "< 1.2.0", advisory.AffectedVersion)
	
	require.NotNil(t, advisory.DataSource, "DataSource should not be nil")
	assert.Equal(t, dbTypes.SourceID("rootio"), advisory.DataSource.ID)
	assert.Equal(t, "Root.io Security Advisory", advisory.DataSource.Name)
	assert.Equal(t, "https://rootio.example.com/advisories", advisory.DataSource.URL)
}

func TestMockVulnSrc_Interface(t *testing.T) {
	// Test that mockVulnSrc properly implements VulnSrc interface
	var vs VulnSrc = newMockVulnSrc()
	
	// This should compile and run without issues if interface is properly implemented
	advisories, err := vs.Get("11", "test-package")
	require.NoError(t, err)
	assert.IsType(t, []dbTypes.Advisory{}, advisories)
}

func TestMockVulnSrc_SimulatesRealImplementation(t *testing.T) {
	t.Run("Mock behavior matches expected trivy-db pattern", func(t *testing.T) {
		vs := newMockVulnSrc()
		
		// Test that mock returns advisories with constraint-format versions
		advisories, err := vs.Get("11", "test-package")
		require.NoError(t, err)
		require.Len(t, advisories, 1)
		
		advisory := advisories[0]
		
		// Verify constraint format (operators with version numbers)
		assert.Contains(t, advisory.FixedVersion, ">=", "FixedVersion should use constraint format")
		assert.Contains(t, advisory.AffectedVersion, "<", "AffectedVersion should use constraint format")
		
		// Verify SourceID pattern in DataSource
		assert.Equal(t, dbTypes.SourceID("rootio"), advisory.DataSource.ID, "DataSource ID should follow SourceID pattern")
	})
}