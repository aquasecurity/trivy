package verify

import (
	"crypto"
	"crypto/ecdsa"
	"math/big"

	"github.com/pkg/errors"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"
)

var ecdsaVerifyFuncs = map[jwa.SignatureAlgorithm]ecdsaVerifyFunc{}

func init() {
	algs := map[jwa.SignatureAlgorithm]crypto.Hash{
		jwa.ES256: crypto.SHA256,
		jwa.ES384: crypto.SHA384,
		jwa.ES512: crypto.SHA512,
	}

	for alg, h := range algs {
		ecdsaVerifyFuncs[alg] = makeECDSAVerifyFunc(h)
	}
}

func makeECDSAVerifyFunc(hash crypto.Hash) ecdsaVerifyFunc {
	return ecdsaVerifyFunc(func(payload []byte, signature []byte, key *ecdsa.PublicKey) error {

		r, s := &big.Int{}, &big.Int{}
		n := len(signature) / 2
		r.SetBytes(signature[:n])
		s.SetBytes(signature[n:])

		h := hash.New()
		h.Write(payload)

		if !ecdsa.Verify(key, h.Sum(nil), r, s) {
			return errors.New(`failed to verify signature using ecdsa`)
		}
		return nil
	})
}

func newECDSA(alg jwa.SignatureAlgorithm) (*ECDSAVerifier, error) {
	verifyfn, ok := ecdsaVerifyFuncs[alg]
	if !ok {
		return nil, errors.Errorf(`unsupported algorithm while trying to create ECDSA verifier: %s`, alg)
	}

	return &ECDSAVerifier{
		verify: verifyfn,
	}, nil
}

// Verify checks whether the signature for a given input and key is correct
func (v ECDSAVerifier) Verify(payload []byte, signature []byte, key interface{}) error {
	if key == nil {
		return errors.New(`missing public key while verifying payload`)
	}
	ecdsakey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return errors.Errorf(`invalid key type %T. *ecdsa.PublicKey is required`, key)
	}

	return v.verify(payload, signature, ecdsakey)
}
