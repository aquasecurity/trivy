package oci

// The identifiers below expose internals to the black-box tests in
// package oci_test.

var (
	ReadLayer              = readLayer
	IsReferrersUnavailable = isReferrersUnavailable
)
