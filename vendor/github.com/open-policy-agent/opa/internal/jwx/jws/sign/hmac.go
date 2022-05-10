package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"

	"github.com/pkg/errors"
)

var hmacSignFuncs = map[jwa.SignatureAlgorithm]hmacSignFunc{}

func init() {
	algs := map[jwa.SignatureAlgorithm]func() hash.Hash{
		jwa.HS256: sha256.New,
		jwa.HS384: sha512.New384,
		jwa.HS512: sha512.New,
	}

	for alg, h := range algs {
		hmacSignFuncs[alg] = makeHMACSignFunc(h)

	}
}

func newHMAC(alg jwa.SignatureAlgorithm) (*HMACSigner, error) {
	signer, ok := hmacSignFuncs[alg]
	if !ok {
		return nil, errors.Errorf(`unsupported algorithm while trying to create HMAC signer: %s`, alg)
	}

	return &HMACSigner{
		alg:  alg,
		sign: signer,
	}, nil
}

func makeHMACSignFunc(hfunc func() hash.Hash) hmacSignFunc {
	return hmacSignFunc(func(payload []byte, key []byte) ([]byte, error) {
		h := hmac.New(hfunc, key)
		h.Write(payload)
		return h.Sum(nil), nil
	})
}

// Algorithm returns the signer algorithm
func (s HMACSigner) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}

// Sign signs payload with a Symmetric  key
func (s HMACSigner) Sign(payload []byte, key interface{}) ([]byte, error) {
	hmackey, ok := key.([]byte)
	if !ok {
		return nil, errors.Errorf(`invalid key type %T. []byte is required`, key)
	}

	if len(hmackey) == 0 {
		return nil, errors.New(`missing key while signing payload`)
	}

	return s.sign(payload, hmackey)
}
