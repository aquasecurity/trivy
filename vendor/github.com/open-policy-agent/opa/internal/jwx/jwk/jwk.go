// Package jwk implements JWK as described in https://tools.ietf.org/html/rfc7517
package jwk

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"

	"github.com/pkg/errors"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"
)

// GetPublicKey returns the public key based on the private key type.
// For rsa key types *rsa.PublicKey is returned; for ecdsa key types *ecdsa.PublicKey;
// for byte slice (raw) keys, the key itself is returned. If the corresponding
// public key cannot be deduced, an error is returned
func GetPublicKey(key interface{}) (interface{}, error) {
	if key == nil {
		return nil, errors.New(`jwk.New requires a non-nil key`)
	}

	switch v := key.(type) {
	// Mental note: although Public() is defined in both types,
	// you can not coalesce the clauses for rsa.PrivateKey and
	// ecdsa.PrivateKey, as then `v` becomes interface{}
	// b/c the compiler cannot deduce the exact type.
	case *rsa.PrivateKey:
		return v.Public(), nil
	case *ecdsa.PrivateKey:
		return v.Public(), nil
	case []byte:
		return v, nil
	default:
		return nil, errors.Errorf(`invalid key type %T`, key)
	}
}

// GetKeyTypeFromKey creates a jwk.Key from the given key.
func GetKeyTypeFromKey(key interface{}) jwa.KeyType {

	switch key.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey:
		return jwa.RSA
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		return jwa.EC
	case []byte:
		return jwa.OctetSeq
	default:
		return jwa.InvalidKeyType
	}
}

// New creates a jwk.Key from the given key.
func New(key interface{}) (Key, error) {
	if key == nil {
		return nil, errors.New(`jwk.New requires a non-nil key`)
	}

	switch v := key.(type) {
	case *rsa.PrivateKey:
		return newRSAPrivateKey(v)
	case *rsa.PublicKey:
		return newRSAPublicKey(v)
	case *ecdsa.PrivateKey:
		return newECDSAPrivateKey(v)
	case *ecdsa.PublicKey:
		return newECDSAPublicKey(v)
	case []byte:
		return newSymmetricKey(v)
	default:
		return nil, errors.Errorf(`invalid key type %T`, key)
	}
}

func parse(jwkSrc string) (*Set, error) {

	var jwkKeySet Set
	var jwkKey Key
	rawKeySetJSON := &RawKeySetJSON{}
	err := json.Unmarshal([]byte(jwkSrc), rawKeySetJSON)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to unmarshal JWK Set")
	}
	if len(rawKeySetJSON.Keys) == 0 {

		// It might be a single key
		rawKeyJSON := &RawKeyJSON{}
		err := json.Unmarshal([]byte(jwkSrc), rawKeyJSON)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to unmarshal JWK")
		}
		jwkKey, err = rawKeyJSON.GenerateKey()
		if err != nil {
			return nil, errors.Wrap(err, "Failed to generate key")
		}
		// Add to set
		jwkKeySet.Keys = append(jwkKeySet.Keys, jwkKey)
	} else {
		for i := range rawKeySetJSON.Keys {
			rawKeyJSON := rawKeySetJSON.Keys[i]
			jwkKey, err = rawKeyJSON.GenerateKey()
			if err != nil {
				return nil, errors.Wrap(err, "Failed to generate key: %s")
			}
			jwkKeySet.Keys = append(jwkKeySet.Keys, jwkKey)
		}
	}
	return &jwkKeySet, nil
}

// ParseBytes parses JWK from the incoming byte buffer.
func ParseBytes(buf []byte) (*Set, error) {
	return parse(string(buf[:]))
}

// ParseString parses JWK from the incoming string.
func ParseString(s string) (*Set, error) {
	return parse(s)
}

// GenerateKey creates an internal representation of a key from a raw JWK JSON
func (r *RawKeyJSON) GenerateKey() (Key, error) {

	var key Key

	switch r.KeyType {
	case jwa.RSA:
		if r.D != nil {
			key = &RSAPrivateKey{}
		} else {
			key = &RSAPublicKey{}
		}
	case jwa.EC:
		if r.D != nil {
			key = &ECDSAPrivateKey{}
		} else {
			key = &ECDSAPublicKey{}
		}
	case jwa.OctetSeq:
		key = &SymmetricKey{}
	default:
		return nil, errors.Errorf(`Unrecognized key type`)
	}
	err := key.GenerateKey(r)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate key from JWK")
	}
	return key, nil
}
