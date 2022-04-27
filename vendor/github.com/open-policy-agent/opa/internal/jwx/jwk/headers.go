package jwk

import (
	"github.com/pkg/errors"

	"github.com/open-policy-agent/opa/internal/jwx/jwa"
)

// Convenience constants for common JWK parameters
const (
	AlgorithmKey     = "alg"
	KeyIDKey         = "kid"
	KeyOpsKey        = "key_ops"
	KeyTypeKey       = "kty"
	KeyUsageKey      = "use"
	PrivateParamsKey = "privateParams"
)

// Headers provides a common interface to all future possible headers
type Headers interface {
	Get(string) (interface{}, bool)
	Set(string, interface{}) error
	Walk(func(string, interface{}) error) error
	GetAlgorithm() jwa.SignatureAlgorithm
	GetKeyID() string
	GetKeyOps() KeyOperationList
	GetKeyType() jwa.KeyType
	GetKeyUsage() string
	GetPrivateParams() map[string]interface{}
}

// StandardHeaders stores the common JWK parameters
type StandardHeaders struct {
	Algorithm     *jwa.SignatureAlgorithm `json:"alg,omitempty"`           // https://tools.ietf.org/html/rfc7517#section-4.4
	KeyID         string                  `json:"kid,omitempty"`           // https://tools.ietf.org/html/rfc7515#section-4.1.4
	KeyOps        KeyOperationList        `json:"key_ops,omitempty"`       // https://tools.ietf.org/html/rfc7517#section-4.3
	KeyType       jwa.KeyType             `json:"kty,omitempty"`           // https://tools.ietf.org/html/rfc7517#section-4.1
	KeyUsage      string                  `json:"use,omitempty"`           // https://tools.ietf.org/html/rfc7517#section-4.2
	PrivateParams map[string]interface{}  `json:"privateParams,omitempty"` // https://tools.ietf.org/html/rfc7515#section-4.1.4
}

// GetAlgorithm is a convenience function to retrieve the corresponding value stored in the StandardHeaders
func (h *StandardHeaders) GetAlgorithm() jwa.SignatureAlgorithm {
	if v := h.Algorithm; v != nil {
		return *v
	}
	return jwa.NoValue
}

// GetKeyID is a convenience function to retrieve the corresponding value stored in the StandardHeaders
func (h *StandardHeaders) GetKeyID() string {
	return h.KeyID
}

// GetKeyOps is a convenience function to retrieve the corresponding value stored in the StandardHeaders
func (h *StandardHeaders) GetKeyOps() KeyOperationList {
	return h.KeyOps
}

// GetKeyType is a convenience function to retrieve the corresponding value stored in the StandardHeaders
func (h *StandardHeaders) GetKeyType() jwa.KeyType {
	return h.KeyType
}

// GetKeyUsage is a convenience function to retrieve the corresponding value stored in the StandardHeaders
func (h *StandardHeaders) GetKeyUsage() string {
	return h.KeyUsage
}

// GetPrivateParams is a convenience function to retrieve the corresponding value stored in the StandardHeaders
func (h *StandardHeaders) GetPrivateParams() map[string]interface{} {
	return h.PrivateParams
}

// Get is a general getter function for JWK StandardHeaders structure
func (h *StandardHeaders) Get(name string) (interface{}, bool) {
	switch name {
	case AlgorithmKey:
		alg := h.GetAlgorithm()
		if alg != jwa.NoValue {
			return alg, true
		}
		return nil, false
	case KeyIDKey:
		v := h.KeyID
		if v == "" {
			return nil, false
		}
		return v, true
	case KeyOpsKey:
		v := h.KeyOps
		if v == nil {
			return nil, false
		}
		return v, true
	case KeyTypeKey:
		v := h.KeyType
		if v == jwa.InvalidKeyType {
			return nil, false
		}
		return v, true
	case KeyUsageKey:
		v := h.KeyUsage
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
	default:
		return nil, false
	}
}

// Set is a general getter function for JWK StandardHeaders structure
func (h *StandardHeaders) Set(name string, value interface{}) error {
	switch name {
	case AlgorithmKey:
		var acceptor jwa.SignatureAlgorithm
		if err := acceptor.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, AlgorithmKey)
		}
		h.Algorithm = &acceptor
		return nil
	case KeyIDKey:
		if v, ok := value.(string); ok {
			h.KeyID = v
			return nil
		}
		return errors.Errorf("invalid value for %s key: %T", KeyIDKey, value)
	case KeyOpsKey:
		if err := h.KeyOps.Accept(value); err != nil {
			return errors.Wrapf(err, "invalid value for %s key", KeyOpsKey)
		}
		return nil
	case KeyTypeKey:
		if err := h.KeyType.Accept(value); err != nil {
			return errors.Wrapf(err, "invalid value for %s key", KeyTypeKey)
		}
		return nil
	case KeyUsageKey:
		if v, ok := value.(string); ok {
			h.KeyUsage = v
			return nil
		}
		return errors.Errorf("invalid value for %s key: %T", KeyUsageKey, value)
	case PrivateParamsKey:
		if v, ok := value.(map[string]interface{}); ok {
			h.PrivateParams = v
			return nil
		}
		return errors.Errorf("invalid value for %s key: %T", PrivateParamsKey, value)
	default:
		return errors.Errorf(`invalid key: %s`, name)
	}
}

// Walk iterates over all JWK standard headers fields while applying a function to its value.
func (h StandardHeaders) Walk(f func(string, interface{}) error) error {
	for _, key := range []string{AlgorithmKey, KeyIDKey, KeyOpsKey, KeyTypeKey, KeyUsageKey, PrivateParamsKey} {
		if v, ok := h.Get(key); ok {
			if err := f(key, v); err != nil {
				return errors.Wrapf(err, `walk function returned error for %s`, key)
			}
		}
	}

	for k, v := range h.PrivateParams {
		if err := f(k, v); err != nil {
			return errors.Wrapf(err, `walk function returned error for %s`, k)
		}
	}
	return nil
}
