package verify

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"
)

// New creates a new JWS verifier using the specified algorithm
// and the public key
func New(alg jwa.SignatureAlgorithm) (Verifier, error) {
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
		return newRSA(alg)
	case jwa.ES256, jwa.ES384, jwa.ES512:
		return newECDSA(alg)
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return newHMAC(alg)
	default:
		return nil, errors.Errorf(`unsupported signature algorithm: %s`, alg)
	}
}

// GetSigningKey returns a *rsa.PublicKey or *ecdsa.PublicKey typically encoded in PEM blocks of type "PUBLIC KEY",
// for RSA and ECDSA family of algorithms.
// For HMAC family, it return a []byte value
func GetSigningKey(key string, alg jwa.SignatureAlgorithm) (interface{}, error) {
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512, jwa.ES256, jwa.ES384, jwa.ES512:
		block, _ := pem.Decode([]byte(key))
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block containing the key")
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		switch pub := pub.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
			return pub, nil
		default:
			return nil, fmt.Errorf("invalid key type %T", pub)
		}
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return []byte(key), nil
	default:
		return nil, errors.Errorf("unsupported signature algorithm: %s", alg)
	}
}
