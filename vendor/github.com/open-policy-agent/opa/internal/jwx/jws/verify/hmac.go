package verify

import (
	"crypto/hmac"

	"github.com/pkg/errors"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"
	"github.com/open-policy-agent/opa/internal/jwx/jws/sign"
)

func newHMAC(alg jwa.SignatureAlgorithm) (*HMACVerifier, error) {

	s, err := sign.New(alg)
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate HMAC signer`)
	}
	return &HMACVerifier{signer: s}, nil
}

// Verify checks whether the signature for a given input and key is correct
func (v HMACVerifier) Verify(signingInput, signature []byte, key interface{}) (err error) {

	expected, err := v.signer.Sign(signingInput, key)
	if err != nil {
		return errors.Wrap(err, `failed to generated signature`)
	}

	if !hmac.Equal(signature, expected) {
		return errors.New(`failed to match hmac signature`)
	}
	return nil
}
