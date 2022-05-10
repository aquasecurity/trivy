// Package jws implements the digital Signature on JSON based data
// structures as described in https://tools.ietf.org/html/rfc7515
//
// If you do not care about the details, the only things that you
// would need to use are the following functions:
//
//     jws.SignWithOption(Payload, algorithm, key)
//     jws.Verify(encodedjws, algorithm, key)
//
// To sign, simply use `jws.SignWithOption`. `Payload` is a []byte buffer that
// contains whatever data you want to sign. `alg` is one of the
// jwa.SignatureAlgorithm constants from package jwa. For RSA and
// ECDSA family of algorithms, you will need to prepare a private key.
// For HMAC family, you just need a []byte value. The `jws.SignWithOption`
// function will return the encoded JWS message on success.
//
// To verify, use `jws.Verify`. It will parse the `encodedjws` buffer
// and verify the result using `algorithm` and `key`. Upon successful
// verification, the original Payload is returned, so you can work on it.
package jws

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"
	"github.com/open-policy-agent/opa/internal/jwx/jwk"
	"github.com/open-policy-agent/opa/internal/jwx/jws/sign"
	"github.com/open-policy-agent/opa/internal/jwx/jws/verify"

	"github.com/pkg/errors"
)

// SignLiteral generates a Signature for the given Payload and Headers, and serializes
// it in compact serialization format. In this format you may NOT use
// multiple signers.
//
func SignLiteral(payload []byte, alg jwa.SignatureAlgorithm, key interface{}, hdrBuf []byte, rnd io.Reader) ([]byte, error) {
	encodedHdr := base64.RawURLEncoding.EncodeToString(hdrBuf)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := strings.Join(
		[]string{
			encodedHdr,
			encodedPayload,
		}, ".",
	)
	signer, err := sign.New(alg)
	if err != nil {
		return nil, errors.Wrap(err, `failed to create signer`)
	}

	var signature []byte
	switch s := signer.(type) {
	case *sign.ECDSASigner:
		signature, err = s.SignWithRand([]byte(signingInput), key, rnd)
	default:
		signature, err = signer.Sign([]byte(signingInput), key)
	}
	if err != nil {
		return nil, errors.Wrap(err, `failed to sign Payload`)
	}
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	compactSerialization := strings.Join(
		[]string{
			signingInput,
			encodedSignature,
		}, ".",
	)
	return []byte(compactSerialization), nil
}

// SignWithOption generates a Signature for the given Payload, and serializes
// it in compact serialization format. In this format you may NOT use
// multiple signers.
//
// If you would like to pass custom Headers, use the WithHeaders option.
func SignWithOption(payload []byte, alg jwa.SignatureAlgorithm, key interface{}) ([]byte, error) {
	var headers Headers = &StandardHeaders{}

	err := headers.Set(AlgorithmKey, alg)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to set alg value")
	}

	hdrBuf, err := json.Marshal(headers)
	if err != nil {
		return nil, errors.Wrap(err, `failed to marshal Headers`)
	}
	// NOTE(sr): we don't use SignWithOption -- if we did, this rand.Reader
	// should come from the BuiltinContext's Seed, too.
	return SignLiteral(payload, alg, key, hdrBuf, rand.Reader)
}

// Verify checks if the given JWS message is verifiable using `alg` and `key`.
// If the verification is successful, `err` is nil, and the content of the
// Payload that was signed is returned. If you need more fine-grained
// control of the verification process, manually call `Parse`, generate a
// verifier, and call `Verify` on the parsed JWS message object.
func Verify(buf []byte, alg jwa.SignatureAlgorithm, key interface{}) (ret []byte, err error) {

	verifier, err := verify.New(alg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create verifier")
	}

	buf = bytes.TrimSpace(buf)
	if len(buf) == 0 {
		return nil, errors.New(`attempt to verify empty buffer`)
	}

	parts, err := SplitCompact(string(buf[:]))
	if err != nil {
		return nil, errors.Wrap(err, `failed extract from compact serialization format`)
	}

	signingInput := strings.Join(
		[]string{
			parts[0],
			parts[1],
		}, ".",
	)

	decodedSignature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.Wrap(err, "Failed to decode signature")
	}
	if err := verifier.Verify([]byte(signingInput), decodedSignature, key); err != nil {
		return nil, errors.Wrap(err, "Failed to verify message")
	}

	if decodedPayload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
		return decodedPayload, nil
	}
	return nil, errors.Wrap(err, "Failed to decode Payload")
}

// VerifyWithJWK verifies the JWS message using the specified JWK
func VerifyWithJWK(buf []byte, key jwk.Key) (payload []byte, err error) {

	keyVal, err := key.Materialize()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to materialize key")
	}
	return Verify(buf, key.GetAlgorithm(), keyVal)
}

// VerifyWithJWKSet verifies the JWS message using JWK key set.
// By default it will only pick up keys that have the "use" key
// set to either "sig" or "enc", but you can override it by
// providing a keyaccept function.
func VerifyWithJWKSet(buf []byte, keyset *jwk.Set) (payload []byte, err error) {

	for _, key := range keyset.Keys {
		payload, err := VerifyWithJWK(buf, key)
		if err == nil {
			return payload, nil
		}
	}
	return nil, errors.New("failed to verify with any of the keys")
}

// ParseByte parses a JWS value serialized via compact serialization and provided as []byte.
func ParseByte(jwsCompact []byte) (m *Message, err error) {
	return parseCompact(string(jwsCompact[:]))
}

// ParseString parses a JWS value serialized via compact serialization and provided as string.
func ParseString(s string) (*Message, error) {
	return parseCompact(s)
}

// SplitCompact splits a JWT and returns its three parts
// separately: Protected Headers, Payload and Signature.
func SplitCompact(jwsCompact string) ([]string, error) {

	parts := strings.Split(jwsCompact, ".")
	if len(parts) < 3 {
		return nil, errors.New("Failed to split compact serialization")
	}
	return parts, nil
}

// parseCompact parses a JWS value serialized via compact serialization.
func parseCompact(str string) (m *Message, err error) {

	var decodedHeader, decodedPayload, decodedSignature []byte
	parts, err := SplitCompact(str)
	if err != nil {
		return nil, errors.Wrap(err, `invalid compact serialization format`)
	}

	if decodedHeader, err = base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		return nil, errors.Wrap(err, `failed to decode Headers`)
	}
	var hdr StandardHeaders
	if err := json.Unmarshal(decodedHeader, &hdr); err != nil {
		return nil, errors.Wrap(err, `failed to parse JOSE Headers`)
	}

	if decodedPayload, err = base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		return nil, errors.Wrap(err, `failed to decode Payload`)
	}

	if len(parts) > 2 {
		if decodedSignature, err = base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
			return nil, errors.Wrap(err, `failed to decode Signature`)
		}
	}

	var msg Message
	msg.Payload = decodedPayload
	msg.Signatures = append(msg.Signatures, &Signature{
		Protected: &hdr,
		Signature: decodedSignature,
	})
	return &msg, nil
}
