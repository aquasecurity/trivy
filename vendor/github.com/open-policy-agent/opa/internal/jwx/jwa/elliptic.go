package jwa

// EllipticCurveAlgorithm represents the algorithms used for EC keys
type EllipticCurveAlgorithm string

// Supported values for EllipticCurveAlgorithm
const (
	P256 EllipticCurveAlgorithm = "P-256"
	P384 EllipticCurveAlgorithm = "P-384"
	P521 EllipticCurveAlgorithm = "P-521"
)
