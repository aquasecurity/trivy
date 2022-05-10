// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package bundle provide helpers that assist in the creating a signed bundle
package bundle

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"
	"github.com/open-policy-agent/opa/internal/jwx/jws"
)

const defaultSignerID = "_default"

var signers map[string]Signer

// Signer is the interface expected for implementations that generate bundle signatures.
type Signer interface {
	GenerateSignedToken([]FileInfo, *SigningConfig, string) (string, error)
}

// GenerateSignedToken will retrieve the Signer implementation based on the Plugin specified
// in SigningConfig, and call its implementation of GenerateSignedToken. The signer generates
// a signed token given the list of files to be included in the payload and the bundle
// signing config. The keyID if non-empty, represents the value for the "keyid" claim in the token.
func GenerateSignedToken(files []FileInfo, sc *SigningConfig, keyID string) (string, error) {
	var plugin string
	// for backwards compatibility, check if there is no plugin specified, and use default
	if sc.Plugin == "" {
		plugin = defaultSignerID
	} else {
		plugin = sc.Plugin
	}
	signer, err := GetSigner(plugin)
	if err != nil {
		return "", err
	}
	return signer.GenerateSignedToken(files, sc, keyID)
}

// DefaultSigner is the default bundle signing implementation. It signs bundles by generating
// a JWT and signing it using a locally-accessible private key.
type DefaultSigner struct{}

// GenerateSignedToken generates a signed token given the list of files to be
// included in the payload and the bundle signing config. The keyID if non-empty,
// represents the value for the "keyid" claim in the token
func (*DefaultSigner) GenerateSignedToken(files []FileInfo, sc *SigningConfig, keyID string) (string, error) {
	payload, err := generatePayload(files, sc, keyID)
	if err != nil {
		return "", err
	}

	privateKey, err := sc.GetPrivateKey()
	if err != nil {
		return "", err
	}

	var headers jws.StandardHeaders

	if err := headers.Set(jws.AlgorithmKey, jwa.SignatureAlgorithm(sc.Algorithm)); err != nil {
		return "", err
	}

	if keyID != "" {
		if err := headers.Set(jws.KeyIDKey, keyID); err != nil {
			return "", err
		}
	}

	hdr, err := json.Marshal(headers)
	if err != nil {
		return "", err
	}

	token, err := jws.SignLiteral(payload,
		jwa.SignatureAlgorithm(sc.Algorithm),
		privateKey,
		hdr,
		rand.Reader)
	if err != nil {
		return "", err
	}
	return string(token), nil
}

func generatePayload(files []FileInfo, sc *SigningConfig, keyID string) ([]byte, error) {
	payload := make(map[string]interface{})
	payload["files"] = files

	if sc.ClaimsPath != "" {
		claims, err := sc.GetClaims()
		if err != nil {
			return nil, err
		}

		for claim, value := range claims {
			payload[claim] = value
		}
	} else {
		if keyID != "" {
			// keyid claim is deprecated but include it for backwards compatibility.
			payload["keyid"] = keyID
		}
	}
	return json.Marshal(payload)
}

// GetSigner returns the Signer registered under the given id
func GetSigner(id string) (Signer, error) {
	signer, ok := signers[id]
	if !ok {
		return nil, fmt.Errorf("no signer exists under id %s", id)
	}
	return signer, nil
}

// RegisterSigner registers a Signer under the given id
func RegisterSigner(id string, s Signer) error {
	if id == defaultSignerID {
		return fmt.Errorf("signer id %s is reserved, use a different id", id)
	}
	signers[id] = s
	return nil
}

func init() {
	signers = map[string]Signer{
		defaultSignerID: &DefaultSigner{},
	}
}
