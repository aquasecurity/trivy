package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"

	"github.com/pkg/errors"
)

var rsaSignFuncs = map[jwa.SignatureAlgorithm]rsaSignFunc{}

func init() {
	algs := map[jwa.SignatureAlgorithm]struct {
		Hash     crypto.Hash
		SignFunc func(crypto.Hash) rsaSignFunc
	}{
		jwa.RS256: {
			Hash:     crypto.SHA256,
			SignFunc: makeSignPKCS1v15,
		},
		jwa.RS384: {
			Hash:     crypto.SHA384,
			SignFunc: makeSignPKCS1v15,
		},
		jwa.RS512: {
			Hash:     crypto.SHA512,
			SignFunc: makeSignPKCS1v15,
		},
		jwa.PS256: {
			Hash:     crypto.SHA256,
			SignFunc: makeSignPSS,
		},
		jwa.PS384: {
			Hash:     crypto.SHA384,
			SignFunc: makeSignPSS,
		},
		jwa.PS512: {
			Hash:     crypto.SHA512,
			SignFunc: makeSignPSS,
		},
	}

	for alg, item := range algs {
		rsaSignFuncs[alg] = item.SignFunc(item.Hash)
	}
}

func makeSignPKCS1v15(hash crypto.Hash) rsaSignFunc {
	return rsaSignFunc(func(payload []byte, key *rsa.PrivateKey) ([]byte, error) {
		h := hash.New()
		h.Write(payload)
		return rsa.SignPKCS1v15(rand.Reader, key, hash, h.Sum(nil))
	})
}

func makeSignPSS(hash crypto.Hash) rsaSignFunc {
	return rsaSignFunc(func(payload []byte, key *rsa.PrivateKey) ([]byte, error) {
		h := hash.New()
		h.Write(payload)
		return rsa.SignPSS(rand.Reader, key, hash, h.Sum(nil), &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		})
	})
}

func newRSA(alg jwa.SignatureAlgorithm) (*RSASigner, error) {
	signfn, ok := rsaSignFuncs[alg]
	if !ok {
		return nil, errors.Errorf(`unsupported algorithm while trying to create RSA signer: %s`, alg)
	}
	return &RSASigner{
		alg:  alg,
		sign: signfn,
	}, nil
}

// Algorithm returns the signer algorithm
func (s RSASigner) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}

// Sign creates a signature using crypto/rsa. key must be a non-nil instance of
// `*"crypto/rsa".PrivateKey`.
func (s RSASigner) Sign(payload []byte, key interface{}) ([]byte, error) {
	if key == nil {
		return nil, errors.New(`missing private key while signing payload`)
	}
	rsakey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.Errorf(`invalid key type %T. *rsa.PrivateKey is required`, key)
	}

	return s.sign(payload, rsakey)
}
