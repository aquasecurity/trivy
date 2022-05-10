package jws

import (
	"github.com/pkg/errors"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"
)

// Constants for JWS Common parameters
const (
	AlgorithmKey     = "alg"
	ContentTypeKey   = "cty"
	CriticalKey      = "crit"
	JWKKey           = "jwk"
	JWKSetURLKey     = "jku"
	KeyIDKey         = "kid"
	PrivateParamsKey = "privateParams"
	TypeKey          = "typ"
)

// Headers provides a common interface for common header parameters
type Headers interface {
	Get(string) (interface{}, bool)
	Set(string, interface{}) error
	GetAlgorithm() jwa.SignatureAlgorithm
}

// StandardHeaders contains JWS common parameters.
type StandardHeaders struct {
	Algorithm     jwa.SignatureAlgorithm `json:"alg,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.1
	ContentType   string                 `json:"cty,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.10
	Critical      []string               `json:"crit,omitempty"`          // https://tools.ietf.org/html/rfc7515#section-4.1.11
	JWK           string                 `json:"jwk,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.3
	JWKSetURL     string                 `json:"jku,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.2
	KeyID         string                 `json:"kid,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.4
	PrivateParams map[string]interface{} `json:"privateParams,omitempty"` // https://tools.ietf.org/html/rfc7515#section-4.1.9
	Type          string                 `json:"typ,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.9
}

// GetAlgorithm returns algorithm
func (h *StandardHeaders) GetAlgorithm() jwa.SignatureAlgorithm {
	return h.Algorithm
}

// Get is a general getter function for StandardHeaders structure
func (h *StandardHeaders) Get(name string) (interface{}, bool) {
	switch name {
	case AlgorithmKey:
		v := h.Algorithm
		if v == "" {
			return nil, false
		}
		return v, true
	case ContentTypeKey:
		v := h.ContentType
		if v == "" {
			return nil, false
		}
		return v, true
	case CriticalKey:
		v := h.Critical
		if len(v) == 0 {
			return nil, false
		}
		return v, true
	case JWKKey:
		v := h.JWK
		if v == "" {
			return nil, false
		}
		return v, true
	case JWKSetURLKey:
		v := h.JWKSetURL
		if v == "" {
			return nil, false
		}
		return v, true
	case KeyIDKey:
		v := h.KeyID
		if v == "" {
			return nil, false
		}
		return v, true
	case PrivateParamsKey:
		v := h.PrivateParams
		if len(v) == 0 {
			return nil, false
		}
		return v, true
	case TypeKey:
		v := h.Type
		if v == "" {
			return nil, false
		}
		return v, true
	default:
		return nil, false
	}
}

// Set is a general setter function for StandardHeaders structure
func (h *StandardHeaders) Set(name string, value interface{}) error {
	switch name {
	case AlgorithmKey:
		if err := h.Algorithm.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, AlgorithmKey)
		}
		return nil
	case ContentTypeKey:
		if v, ok := value.(string); ok {
			h.ContentType = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ContentTypeKey, value)
	case CriticalKey:
		if v, ok := value.([]string); ok {
			h.Critical = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, CriticalKey, value)
	case JWKKey:
		if v, ok := value.(string); ok {
			h.JWK = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, JWKKey, value)
	case JWKSetURLKey:
		if v, ok := value.(string); ok {
			h.JWKSetURL = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, JWKSetURLKey, value)
	case KeyIDKey:
		if v, ok := value.(string); ok {
			h.KeyID = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, KeyIDKey, value)
	case PrivateParamsKey:
		if v, ok := value.(map[string]interface{}); ok {
			h.PrivateParams = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, PrivateParamsKey, value)
	case TypeKey:
		if v, ok := value.(string); ok {
			h.Type = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, TypeKey, value)
	default:
		return errors.Errorf(`invalid key: %s`, name)
	}
}
