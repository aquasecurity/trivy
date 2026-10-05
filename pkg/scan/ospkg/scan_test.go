package ospkg_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ospkgDetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
)

type mockDriver struct {
	called bool
	vulns  []types.DetectedVulnerability
}

func (m *mockDriver) Detect(_ context.Context, _ string, _ *ftypes.Repository, _ []ftypes.Package) ([]types.DetectedVulnerability, error) {
	m.called = true
	return m.vulns, nil
}

func (m *mockDriver) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}

// TestScanner_Scan_ForwardsOptions verifies that options passed to NewScanner
// are forwarded to ospkgDetector.NewDetector during Scan.
func TestScanner_Scan_ForwardsOptions(t *testing.T) {
	target := types.ScanTarget{
		OS: ftypes.OS{
			Family: ftypes.CentOS,
			Name:   "7",
		},
		Packages: []ftypes.Package{
			{Name: "vim"},
		},
	}
	opts := types.ScanOptions{
		Scanners: types.Scanners{types.VulnerabilityScanner},
	}

	want := []types.DetectedVulnerability{
		{VulnerabilityID: "CVE-2024-0001"},
	}

	mockDrv := &mockDriver{vulns: want}
	s := ospkg.NewScanner(ospkgDetector.WithDriver(target.OS.Family, mockDrv))

	result, _, err := s.Scan(t.Context(), target, opts)
	require.NoError(t, err)

	assert.True(t, mockDrv.called, "expected the driver registered via the option to be used")
	assert.Equal(t, want, result.Vulnerabilities)
}
