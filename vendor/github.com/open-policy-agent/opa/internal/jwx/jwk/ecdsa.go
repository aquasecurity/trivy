package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/pkg/errors"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"
)

func newECDSAPublicKey(key *ecdsa.PublicKey) (*ECDSAPublicKey, error) {

	var hdr StandardHeaders
	err := hdr.Set(KeyTypeKey, jwa.EC)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to set Key Type")
	}

	return &ECDSAPublicKey{
		StandardHeaders: &hdr,
		key:             key,
	}, nil
}

func newECDSAPrivateKey(key *ecdsa.PrivateKey) (*ECDSAPrivateKey, error) {

	var hdr StandardHeaders
	err := hdr.Set(KeyTypeKey, jwa.EC)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to set Key Type")
	}

	return &ECDSAPrivateKey{
		StandardHeaders: &hdr,
		key:             key,
	}, nil
}

// Materialize returns the EC-DSA public key represented by this JWK
func (k ECDSAPublicKey) Materialize() (interface{}, error) {
	return k.key, nil
}

// Materialize returns the EC-DSA private key represented by this JWK
func (k ECDSAPrivateKey) Materialize() (interface{}, error) {
	return k.key, nil
}

// GenerateKey creates a ECDSAPublicKey from JWK format
func (k *ECDSAPublicKey) GenerateKey(keyJSON *RawKeyJSON) error {

	var x, y big.Int

	if keyJSON.X == nil || keyJSON.Y == nil || keyJSON.Crv == "" {
		return errors.Errorf("Missing mandatory key parameters X, Y or Crv")
	}

	x.SetBytes(keyJSON.X.Bytes())
	y.SetBytes(keyJSON.Y.Bytes())

	var curve elliptic.Curve
	switch keyJSON.Crv {
	case jwa.P256:
		curve = elliptic.P256()
	case jwa.P384:
		curve = elliptic.P384()
	case jwa.P521:
		curve = elliptic.P521()
	default:
		return errors.Errorf(`invalid curve name %s`, keyJSON.Crv)
	}

	*k = ECDSAPublicKey{
		StandardHeaders: &keyJSON.StandardHeaders,
		key: &ecdsa.PublicKey{
			Curve: curve,
			X:     &x,
			Y:     &y,
		},
	}
	return nil
}

// GenerateKey creates a ECDSAPrivateKey from JWK format
func (k *ECDSAPrivateKey) GenerateKey(keyJSON *RawKeyJSON) error {

	if keyJSON.D == nil {
		return errors.Errorf("Missing mandatory key parameter D")
	}
	eCDSAPublicKey := &ECDSAPublicKey{}
	err := eCDSAPublicKey.GenerateKey(keyJSON)
	if err != nil {
		return errors.Wrap(err, `failed to generate public key`)
	}
	dBytes := keyJSON.D.Bytes()
	// The length of this octet string MUST be ceiling(log-base-2(n)/8)
	// octets (where n is the order of the curve). This is because the private
	// key d must be in the interval [1, n-1] so the bitlength of d should be
	// no larger than the bitlength of n-1. The easiest way to find the octet
	// length is to take bitlength(n-1), add 7 to force a carry, and shift this
	// bit sequence right by 3, which is essentially dividing by 8 and adding
	// 1 if there is any remainder. Thus, the private key value d should be
	// output to (bitlength(n-1)+7)>>3 octets.
	n := eCDSAPublicKey.key.Params().N
	octetLength := (new(big.Int).Sub(n, big.NewInt(1)).BitLen() + 7) >> 3
	if octetLength-len(dBytes) != 0 {
		return errors.Errorf("Failed to generate private key. Incorrect D value")
	}
	privateKey := &ecdsa.PrivateKey{
		PublicKey: *eCDSAPublicKey.key,
		D:         (&big.Int{}).SetBytes(keyJSON.D.Bytes()),
	}

	k.key = privateKey
	k.StandardHeaders = &keyJSON.StandardHeaders

	return nil
}
