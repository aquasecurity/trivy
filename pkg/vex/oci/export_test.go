package oci

import "testing"

// The identifiers below expose internals to the black-box tests in
// package oci_test.

var (
	ReadLayer              = readLayer
	IsReferrersUnavailable = isReferrersUnavailable
)

// SetMaxAttestationSize lowers the per-layer size limit for the duration of the
// test, so the limit can be exercised without materializing a full-sized layer.
func SetMaxAttestationSize(t *testing.T, n int) {
	t.Helper()
	old := maxAttestationSize
	maxAttestationSize = n
	t.Cleanup(func() { maxAttestationSize = old })
}
