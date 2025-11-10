package notification

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateMachineHash(t *testing.T) {
	// Test with known input
	identifier := "test-identifier"
	hash := generateMachineHash(identifier)

	// Known hash for "test-identifier"
	expectedHash := "115ae872eb1d3e23f9de03f7ab344193b21068812ee52eb37e8169e6d093c7ae"
	assert.Equal(t, expectedHash, hash)
}

// This test requires some modification to the original code to make it testable
// by injecting mocked network interfaces
func TestGetMachineIdentifier(t *testing.T) {
	// This is a basic test that at least ensures the function returns without error
	// A more complete test would mock os.Hostname and net.Interfaces
	identifier, err := getMachineIdentifier()
	require.NoError(t, err)
	require.NotEmpty(t, identifier)
}
