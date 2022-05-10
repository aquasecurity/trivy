package jwk

import (
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"
)

// Set is a convenience struct to allow generating and parsing
// JWK sets as opposed to single JWKs
type Set struct {
	Keys []Key `json:"keys"`
}

// Key defines the minimal interface for each of the
// key types. Their use and implementation differ significantly
// between each key types, so you should use type assertions
// to perform more specific tasks with each key
type Key interface {
	Headers

	// Materialize creates the corresponding key. For example,
	// RSA types would create *rsa.PublicKey or *rsa.PrivateKey,
	// EC types would create *ecdsa.PublicKey or *ecdsa.PrivateKey,
	// and OctetSeq types create a []byte key.
	Materialize() (interface{}, error)
	GenerateKey(*RawKeyJSON) error
}

// RawKeyJSON is generic type that represents any kind JWK
type RawKeyJSON struct {
	StandardHeaders
	jwa.AlgorithmParameters
}

// RawKeySetJSON is generic type that represents a JWK Set
type RawKeySetJSON struct {
	Keys []RawKeyJSON `json:"keys"`
}

// RSAPublicKey is a type of JWK generated from RSA public keys
type RSAPublicKey struct {
	*StandardHeaders
	key *rsa.PublicKey
}

// RSAPrivateKey is a type of JWK generated from RSA private keys
type RSAPrivateKey struct {
	*StandardHeaders
	*jwa.AlgorithmParameters
	key *rsa.PrivateKey
}

// SymmetricKey is a type of JWK generated from symmetric keys
type SymmetricKey struct {
	*StandardHeaders
	key []byte
}

// ECDSAPublicKey is a type of JWK generated from ECDSA public keys
type ECDSAPublicKey struct {
	*StandardHeaders
	key *ecdsa.PublicKey
}

// ECDSAPrivateKey is a type of JWK generated from ECDH-ES private keys
type ECDSAPrivateKey struct {
	*StandardHeaders
	key *ecdsa.PrivateKey
}
