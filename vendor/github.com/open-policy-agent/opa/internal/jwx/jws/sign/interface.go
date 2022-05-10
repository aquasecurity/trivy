package sign

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"io"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"
)

// Signer provides a common interface for supported alg signing methods
type Signer interface {
	// Sign creates a signature for the given `payload`.
	// `key` is the key used for signing the payload, and is usually
	// the private key type associated with the signature method. For example,
	// for `jwa.RSXXX` and `jwa.PSXXX` types, you need to pass the
	// `*"crypto/rsa".PrivateKey` type.
	// Check the documentation for each signer for details
	Sign(payload []byte, key interface{}) ([]byte, error)

	Algorithm() jwa.SignatureAlgorithm
}

type rsaSignFunc func([]byte, *rsa.PrivateKey) ([]byte, error)

// RSASigner uses crypto/rsa to sign the payloads.
type RSASigner struct {
	alg  jwa.SignatureAlgorithm
	sign rsaSignFunc
}

type ecdsaSignFunc func([]byte, *ecdsa.PrivateKey, io.Reader) ([]byte, error)

// ECDSASigner uses crypto/ecdsa to sign the payloads.
type ECDSASigner struct {
	alg  jwa.SignatureAlgorithm
	sign ecdsaSignFunc
}

type hmacSignFunc func([]byte, []byte) ([]byte, error)

// HMACSigner uses crypto/hmac to sign the payloads.
type HMACSigner struct {
	alg  jwa.SignatureAlgorithm
	sign hmacSignFunc
}
