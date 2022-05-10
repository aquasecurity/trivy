package sign

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"
)

// New creates a signer that signs payloads using the given signature algorithm.
func New(alg jwa.SignatureAlgorithm) (Signer, error) {
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
		return newRSA(alg)
	case jwa.ES256, jwa.ES384, jwa.ES512:
		return newECDSA(alg)
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return newHMAC(alg)
	default:
		return nil, errors.Errorf(`unsupported signature algorithm %s`, alg)
	}
}

// GetSigningKey returns a *rsa.PrivateKey or *ecdsa.PrivateKey typically encoded in PEM blocks of type "RSA PRIVATE KEY"
// or "EC PRIVATE KEY" for RSA and ECDSA family of algorithms.
// For HMAC family, it return a []byte value
func GetSigningKey(key string, alg jwa.SignatureAlgorithm) (interface{}, error) {
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
		block, _ := pem.Decode([]byte(key))
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block containing the key")
		}

		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			pkcs8priv, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("error parsing private key (%v), (%v)", err, err2)
			}
			return pkcs8priv, nil
		}
		return priv, nil
	case jwa.ES256, jwa.ES384, jwa.ES512:
		block, _ := pem.Decode([]byte(key))
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block containing the key")
		}

		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			pkcs8priv, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("error parsing private key (%v), (%v)", err, err2)
			}
			return pkcs8priv, nil
		}
		return priv, nil
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return []byte(key), nil
	default:
		return nil, errors.Errorf("unsupported signature algorithm: %s", alg)
	}
}
