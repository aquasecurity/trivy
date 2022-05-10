package jwa

import (
	"crypto/elliptic"

	"github.com/open-policy-agent/opa/internal/jwx/buffer"
)

// EllipticCurve provides a indirect type to standard elliptic curve such that we can
// use it for unmarshal
type EllipticCurve struct {
	elliptic.Curve
}

// AlgorithmParameters provides a single structure suitable to unmarshaling any JWK
type AlgorithmParameters struct {
	N   buffer.Buffer          `json:"n,omitempty"`
	E   buffer.Buffer          `json:"e,omitempty"`
	D   buffer.Buffer          `json:"d,omitempty"`
	P   buffer.Buffer          `json:"p,omitempty"`
	Q   buffer.Buffer          `json:"q,omitempty"`
	Dp  buffer.Buffer          `json:"dp,omitempty"`
	Dq  buffer.Buffer          `json:"dq,omitempty"`
	Qi  buffer.Buffer          `json:"qi,omitempty"`
	Crv EllipticCurveAlgorithm `json:"crv,omitempty"`
	X   buffer.Buffer          `json:"x,omitempty"`
	Y   buffer.Buffer          `json:"y,omitempty"`
	K   buffer.Buffer          `json:"k,omitempty"`
}
