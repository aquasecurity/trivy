package keys

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/open-policy-agent/opa/util"
)

const defaultSigningAlgorithm = "RS256"

var supportedAlgos = map[string]struct{}{
	"ES256": {}, "ES384": {}, "ES512": {},
	"HS256": {}, "HS384": {}, "HS512": {},
	"PS256": {}, "PS384": {}, "PS512": {},
	"RS256": {}, "RS384": {}, "RS512": {},
}

// IsSupportedAlgorithm true if provided alg is supported
func IsSupportedAlgorithm(alg string) bool {
	_, ok := supportedAlgos[alg]
	return ok
}

// Config holds the keys used to sign or verify bundles and tokens
type Config struct {
	Key        string `json:"key"`
	PrivateKey string `json:"private_key"`
	Algorithm  string `json:"algorithm"`
	Scope      string `json:"scope"`
}

// Equal returns true if this key config is equal to the other.
func (k *Config) Equal(other *Config) bool {
	return other != nil && *k == *other
}

func (k *Config) validateAndInjectDefaults(id string) error {
	if k.Key == "" && k.PrivateKey == "" {
		return fmt.Errorf("invalid keys configuration: no keys provided for key ID %v", id)
	}

	if k.Algorithm == "" {
		k.Algorithm = defaultSigningAlgorithm
	}

	if !IsSupportedAlgorithm(k.Algorithm) {
		return fmt.Errorf("unsupported algorithm '%v'", k.Algorithm)
	}

	return nil
}

// NewKeyConfig return a new Config
func NewKeyConfig(key, alg, scope string) (*Config, error) {
	var pubKey string
	if _, err := os.Stat(key); err == nil {
		bs, err := ioutil.ReadFile(key)
		if err != nil {
			return nil, err
		}
		pubKey = string(bs)
	} else if os.IsNotExist(err) {
		pubKey = key
	} else {
		return nil, err
	}

	return &Config{
		Key:       pubKey,
		Algorithm: alg,
		Scope:     scope,
	}, nil
}

// ParseKeysConfig returns a map containing the key and the signing algorithm
func ParseKeysConfig(raw json.RawMessage) (map[string]*Config, error) {
	keys := map[string]*Config{}
	var obj map[string]json.RawMessage

	if err := util.Unmarshal(raw, &obj); err == nil {
		for k := range obj {
			var keyConfig Config
			if err = util.Unmarshal(obj[k], &keyConfig); err != nil {
				return nil, err
			}

			if err = keyConfig.validateAndInjectDefaults(k); err != nil {
				return nil, err
			}

			keys[k] = &keyConfig
		}
	} else {
		return nil, err
	}
	return keys, nil
}
