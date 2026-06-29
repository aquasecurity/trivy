package vex

import "testing"

// IsReferrersUnsupported exposes isReferrersUnsupported for testing.
var IsReferrersUnsupported = isReferrersUnsupported

// SetMaxAttestationSize lowers the attestation layer size limit for the
// duration of a test.
func SetMaxAttestationSize(t *testing.T, n int) {
	t.Helper()
	old := maxAttestationSize
	maxAttestationSize = n
	t.Cleanup(func() { maxAttestationSize = old })
}
