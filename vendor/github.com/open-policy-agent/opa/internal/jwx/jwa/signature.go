package jwa

import (
	"strconv"

	"github.com/pkg/errors"
)

// SignatureAlgorithm represents the various signature algorithms as described in https://tools.ietf.org/html/rfc7518#section-3.1
type SignatureAlgorithm string

var signatureAlg = map[string]struct{}{"ES256": {}, "ES384": {}, "ES512": {}, "HS256": {}, "HS384": {}, "HS512": {}, "PS256": {}, "PS384": {}, "PS512": {}, "RS256": {}, "RS384": {}, "RS512": {}, "none": {}}

// Supported values for SignatureAlgorithm
const (
	ES256       SignatureAlgorithm = "ES256" // ECDSA using P-256 and SHA-256
	ES384       SignatureAlgorithm = "ES384" // ECDSA using P-384 and SHA-384
	ES512       SignatureAlgorithm = "ES512" // ECDSA using P-521 and SHA-512
	HS256       SignatureAlgorithm = "HS256" // HMAC using SHA-256
	HS384       SignatureAlgorithm = "HS384" // HMAC using SHA-384
	HS512       SignatureAlgorithm = "HS512" // HMAC using SHA-512
	NoSignature SignatureAlgorithm = "none"
	PS256       SignatureAlgorithm = "PS256" // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384       SignatureAlgorithm = "PS384" // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512       SignatureAlgorithm = "PS512" // RSASSA-PSS using SHA512 and MGF1-SHA512
	RS256       SignatureAlgorithm = "RS256" // RSASSA-PKCS-v1.5 using SHA-256
	RS384       SignatureAlgorithm = "RS384" // RSASSA-PKCS-v1.5 using SHA-384
	RS512       SignatureAlgorithm = "RS512" // RSASSA-PKCS-v1.5 using SHA-512
	NoValue     SignatureAlgorithm = ""      // No value is different from none
)

// Accept is used when conversion from values given by
// outside sources (such as JSON payloads) is required
func (signature *SignatureAlgorithm) Accept(value interface{}) error {
	var tmp SignatureAlgorithm
	switch x := value.(type) {
	case string:
		tmp = SignatureAlgorithm(x)
	case SignatureAlgorithm:
		tmp = x
	default:
		return errors.Errorf(`invalid type for jwa.SignatureAlgorithm: %T`, value)
	}
	_, ok := signatureAlg[tmp.String()]
	if !ok {
		return errors.Errorf("Unknown signature algorithm")
	}
	*signature = tmp
	return nil
}

// String returns the string representation of a SignatureAlgorithm
func (signature SignatureAlgorithm) String() string {
	return string(signature)
}

// UnmarshalJSON unmarshals and checks data as Signature Algorithm
func (signature *SignatureAlgorithm) UnmarshalJSON(data []byte) error {
	var quote byte = '"'
	var quoted string
	if data[0] == quote {
		var err error
		quoted, err = strconv.Unquote(string(data))
		if err != nil {
			return errors.Wrap(err, "Failed to process signature algorithm")
		}
	} else {
		quoted = string(data)
	}
	_, ok := signatureAlg[quoted]
	if !ok {
		return errors.Errorf("Unknown signature algorithm")
	}
	*signature = SignatureAlgorithm(quoted)
	return nil
}
