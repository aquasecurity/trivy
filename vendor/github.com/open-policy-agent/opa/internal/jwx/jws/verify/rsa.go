package verify

import (
	"crypto"
	"crypto/rsa"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"

	"github.com/pkg/errors"
)

var rsaVerifyFuncs = map[jwa.SignatureAlgorithm]rsaVerifyFunc{}

func init() {
	algs := map[jwa.SignatureAlgorithm]struct {
		Hash       crypto.Hash
		VerifyFunc func(crypto.Hash) rsaVerifyFunc
	}{
		jwa.RS256: {
			Hash:       crypto.SHA256,
			VerifyFunc: makeVerifyPKCS1v15,
		},
		jwa.RS384: {
			Hash:       crypto.SHA384,
			VerifyFunc: makeVerifyPKCS1v15,
		},
		jwa.RS512: {
			Hash:       crypto.SHA512,
			VerifyFunc: makeVerifyPKCS1v15,
		},
		jwa.PS256: {
			Hash:       crypto.SHA256,
			VerifyFunc: makeVerifyPSS,
		},
		jwa.PS384: {
			Hash:       crypto.SHA384,
			VerifyFunc: makeVerifyPSS,
		},
		jwa.PS512: {
			Hash:       crypto.SHA512,
			VerifyFunc: makeVerifyPSS,
		},
	}

	for alg, item := range algs {
		rsaVerifyFuncs[alg] = item.VerifyFunc(item.Hash)
	}
}

func makeVerifyPKCS1v15(hash crypto.Hash) rsaVerifyFunc {
	return rsaVerifyFunc(func(payload, signature []byte, key *rsa.PublicKey) error {
		h := hash.New()
		h.Write(payload)
		return rsa.VerifyPKCS1v15(key, hash, h.Sum(nil), signature)
	})
}

func makeVerifyPSS(hash crypto.Hash) rsaVerifyFunc {
	return rsaVerifyFunc(func(payload, signature []byte, key *rsa.PublicKey) error {
		h := hash.New()
		h.Write(payload)
		return rsa.VerifyPSS(key, hash, h.Sum(nil), signature, nil)
	})
}

func newRSA(alg jwa.SignatureAlgorithm) (*RSAVerifier, error) {
	verifyfn, ok := rsaVerifyFuncs[alg]
	if !ok {
		return nil, errors.Errorf(`unsupported algorithm while trying to create RSA verifier: %s`, alg)
	}

	return &RSAVerifier{
		verify: verifyfn,
	}, nil
}

// Verify checks if a JWS is valid.
func (v RSAVerifier) Verify(payload, signature []byte, key interface{}) error {
	if key == nil {
		return errors.New(`missing public key while verifying payload`)
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.Errorf(`invalid key type %T. *rsa.PublicKey is required`, key)
	}

	return v.verify(payload, signature, rsaKey)
}
