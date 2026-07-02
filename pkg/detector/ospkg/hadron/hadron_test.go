package hadron

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestScanner_Detect(t *testing.T) {
	s := NewScanner()
	pkgs := []ftypes.Package{
		{Name: "openssl", Version: "3.6.3"},
		{Name: "curl", Version: "8.21.0"},
	}

	vulns, err := s.Detect(t.Context(), "main", nil, pkgs)
	require.NoError(t, err)
	assert.Empty(t, vulns)
}

func TestScanner_IsSupportedVersion(t *testing.T) {
	s := NewScanner()
	// Hadron is a rolling release: always supported.
	assert.True(t, s.IsSupportedVersion(t.Context(), ftypes.Hadron, "main"))
}
