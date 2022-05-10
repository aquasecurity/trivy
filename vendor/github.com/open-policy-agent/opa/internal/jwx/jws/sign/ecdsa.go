package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"io"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"

	"github.com/pkg/errors"
)

var ecdsaSignFuncs = map[jwa.SignatureAlgorithm]ecdsaSignFunc{}

func init() {
	algs := map[jwa.SignatureAlgorithm]crypto.Hash{
		jwa.ES256: crypto.SHA256,
		jwa.ES384: crypto.SHA384,
		jwa.ES512: crypto.SHA512,
	}

	for alg, h := range algs {
		ecdsaSignFuncs[alg] = makeECDSASignFunc(h)
	}
}

func makeECDSASignFunc(hash crypto.Hash) ecdsaSignFunc {
	return ecdsaSignFunc(func(payload []byte, key *ecdsa.PrivateKey, rnd io.Reader) ([]byte, error) {
		curveBits := key.Curve.Params().BitSize
		keyBytes := curveBits / 8
		// Curve bits do not need to be a multiple of 8.
		if curveBits%8 > 0 {
			keyBytes++
		}
		h := hash.New()
		h.Write(payload)
		r, s, err := ecdsa.Sign(rnd, key, h.Sum(nil))
		if err != nil {
			return nil, errors.Wrap(err, "failed to sign payload using ecdsa")
		}

		rBytes := r.Bytes()
		rBytesPadded := make([]byte, keyBytes)
		copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

		sBytes := s.Bytes()
		sBytesPadded := make([]byte, keyBytes)
		copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

		out := append(rBytesPadded, sBytesPadded...)
		return out, nil
	})
}

func newECDSA(alg jwa.SignatureAlgorithm) (*ECDSASigner, error) {
	signfn, ok := ecdsaSignFuncs[alg]
	if !ok {
		return nil, errors.Errorf(`unsupported algorithm while trying to create ECDSA signer: %s`, alg)
	}

	return &ECDSASigner{
		alg:  alg,
		sign: signfn,
	}, nil
}

// Algorithm returns the signer algorithm
func (s ECDSASigner) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}

// SignWithRand signs payload with a ECDSA private key and a provided randomness
// source (such as `rand.Reader`).
func (s ECDSASigner) SignWithRand(payload []byte, key interface{}, r io.Reader) ([]byte, error) {
	if key == nil {
		return nil, errors.New(`missing private key while signing payload`)
	}

	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.Errorf(`invalid key type %T. *ecdsa.PrivateKey is required`, key)
	}
	return s.sign(payload, privateKey, r)
}

// Sign signs payload with a ECDSA private key
func (s ECDSASigner) Sign(payload []byte, key interface{}) ([]byte, error) {
	return s.SignWithRand(payload, key, rand.Reader)
}
