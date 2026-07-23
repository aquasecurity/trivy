package crypto

import (
	"encoding/json"
	"net/url"
	"strings"

	"golang.org/x/xerrors"
)

// Descriptor is the comparable canonical identity of an asset.
type Descriptor struct {
	Kind     Kind     `json:",omitempty"`
	KeyType  KeyType  `json:",omitempty"`
	Identity Identity `json:",omitzero"`
}

// String returns the canonical encoded descriptor.
func (d Descriptor) String() string {
	segments := []string{string(d.Kind)}
	if d.Kind == KindKey {
		segments = append(segments, string(d.KeyType))
	}
	// QueryEscape uses the standard library's query-component encoding for
	// variable segments. It escapes RFC 3986 reserved characters, including the
	// descriptor's colon delimiter, and represents spaces as '+'.
	segments = append(segments, string(d.Identity.Method), url.QueryEscape(d.Identity.Value))
	// Parameters distinguish algorithm assets that share an OID but use different
	// key sizes or curves.
	if d.Identity.Parameters != "" {
		segments = append(segments, url.QueryEscape(d.Identity.Parameters))
	}
	return strings.Join(segments, ":")
}

// MarshalJSON validates and encodes the descriptor as its canonical string.
func (d Descriptor) MarshalJSON() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, xerrors.Errorf("validate descriptor: %w", err)
	}
	encoded, err := json.Marshal(d.String())
	if err != nil {
		return nil, xerrors.Errorf("encode descriptor: %w", err)
	}
	return encoded, nil
}

// UnmarshalJSON decodes and validates a descriptor string.
func (d *Descriptor) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return xerrors.Errorf("decode descriptor: %w", err)
	}

	descriptor, err := parseDescriptor(s)
	if err != nil {
		return xerrors.Errorf("parse descriptor: %w", err)
	}
	*d = descriptor
	return nil
}

// Validate checks that the descriptor is structurally valid and canonical.
func (d Descriptor) Validate() error {
	if err := d.validateKindKeyTypeMethod(); err != nil {
		return xerrors.Errorf("validate kind, key type, and method: %w", err)
	}
	if err := d.validateIdentityValue(); err != nil {
		return xerrors.Errorf("validate identity value: %w", err)
	}
	if err := d.validateParameters(); err != nil {
		return xerrors.Errorf("validate parameters: %w", err)
	}
	return nil
}

func (d Descriptor) validateKindKeyTypeMethod() error {
	switch d.Kind {
	case KindCertificate:
		if d.KeyType != "" {
			return xerrors.Errorf("certificate descriptor must not contain key type %q", d.KeyType)
		}
		if d.Identity.Method != MethodSHA256 {
			return xerrors.Errorf("certificate descriptor requires identification method %q", MethodSHA256)
		}
	case KindKey:
		switch d.KeyType {
		case KeyTypePublic:
			if d.Identity.Method != MethodSPKISHA256 {
				return xerrors.Errorf("public key descriptor requires identification method %q", MethodSPKISHA256)
			}
		case KeyTypePrivate:
			if d.Identity.Method != MethodSPKISHA256 && d.Identity.Method != MethodEncryptedPKCS8SHA256 {
				return xerrors.Errorf("private key descriptor has unknown identification method %q", d.Identity.Method)
			}
		default:
			return xerrors.Errorf("unknown key type %q", d.KeyType)
		}
	case KindAlgorithm:
		if d.KeyType != "" {
			return xerrors.Errorf("algorithm descriptor must not contain key type %q", d.KeyType)
		}
		if d.Identity.Method != MethodOID {
			return xerrors.Errorf("algorithm descriptor requires identification method %q", MethodOID)
		}
	default:
		return xerrors.Errorf("unknown asset kind %q", d.Kind)
	}
	return nil
}

func (d Descriptor) validateIdentityValue() error {
	switch d.Identity.Method {
	case MethodSHA256, MethodSPKISHA256, MethodEncryptedPKCS8SHA256:
		if !isLowerSHA256(d.Identity.Value) {
			return xerrors.Errorf("identification value must be 64 lowercase hexadecimal characters")
		}
	case MethodOID:
		if !isCanonicalOID(d.Identity.Value) {
			return xerrors.Errorf("identification value must be a canonical OID")
		}
	}
	return nil
}

func (d Descriptor) validateParameters() error {
	if d.Identity.Parameters == "" {
		return nil
	}
	if d.Kind != KindAlgorithm || d.Identity.Method != MethodOID {
		return xerrors.Errorf("parameters are only valid for OID algorithm descriptors")
	}
	if err := validateAlgorithmParameters(d.Identity.Parameters); err != nil {
		return xerrors.Errorf("validate algorithm parameters: %w", err)
	}
	return nil
}

func parseDescriptor(s string) (Descriptor, error) {
	segments := strings.Split(s, ":")
	var descriptor Descriptor
	var valueSegment string
	var parametersSegment string

	switch Kind(segments[0]) {
	case KindCertificate:
		if len(segments) != 3 {
			return Descriptor{}, xerrors.Errorf("certificate descriptor must contain 3 segments")
		}
		descriptor.Kind = KindCertificate
		descriptor.Identity.Method = IdentityMethod(segments[1])
		valueSegment = segments[2]
	case KindKey:
		if len(segments) != 4 {
			return Descriptor{}, xerrors.Errorf("key descriptor must contain 4 segments")
		}
		descriptor.Kind = KindKey
		descriptor.KeyType = KeyType(segments[1])
		descriptor.Identity.Method = IdentityMethod(segments[2])
		valueSegment = segments[3]
	case KindAlgorithm:
		if len(segments) != 3 && len(segments) != 4 {
			return Descriptor{}, xerrors.Errorf("algorithm descriptor must contain 3 or 4 segments")
		}
		descriptor.Kind = KindAlgorithm
		descriptor.Identity.Method = IdentityMethod(segments[1])
		valueSegment = segments[2]
		if len(segments) == 4 {
			parametersSegment = segments[3]
			if parametersSegment == "" {
				return Descriptor{}, xerrors.Errorf("algorithm descriptor parameters must not be empty")
			}
		}
	default:
		return Descriptor{}, xerrors.Errorf("unknown descriptor kind %q", segments[0])
	}

	value, err := url.QueryUnescape(valueSegment)
	if err != nil {
		return Descriptor{}, xerrors.Errorf("decode identification value: %w", err)
	}
	descriptor.Identity.Value = value
	if len(segments) == 4 && descriptor.Kind == KindAlgorithm {
		parameters, err := url.QueryUnescape(parametersSegment)
		if err != nil {
			return Descriptor{}, xerrors.Errorf("decode identification parameters: %w", err)
		}
		descriptor.Identity.Parameters = parameters
	}

	if err := descriptor.Validate(); err != nil {
		return Descriptor{}, xerrors.Errorf("validate descriptor: %w", err)
	}
	return descriptor, nil
}

// validateAlgorithmParameters accepts only empty parameters, key-size=<canonical positive
// decimal>, and curve=<non-empty name>.
func validateAlgorithmParameters(parameters string) error {
	if parameters == "" {
		return nil
	}
	if value, ok := strings.CutPrefix(parameters, "key-size="); ok {
		if !isCanonicalPositiveDecimal(value) {
			return xerrors.Errorf("key size parameter must be a canonical positive decimal")
		}
		return nil
	}
	if value, ok := strings.CutPrefix(parameters, "curve="); ok {
		if value == "" {
			return xerrors.Errorf("curve parameter must not be empty")
		}
		return nil
	}
	return xerrors.Errorf("unknown algorithm parameters %q", parameters)
}

func isLowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

// isCanonicalOID reports whether value uses RFC 4512 section 1.4's numeric OID
// form and satisfies the root-arc constraints from ITU-T X.660 section 7.6. It
// does not validate every ASN.1 OID notation.
//
// RFC 4512: https://www.rfc-editor.org/rfc/rfc4512.html#section-1.4
// ITU-T X.660: https://www.itu.int/rec/T-REC-X.660-201107-I/en
func isCanonicalOID(value string) bool {
	arcs := strings.Split(value, ".")
	if len(arcs) < 2 {
		return false
	}
	for _, arc := range arcs {
		if !isCanonicalDecimal(arc) {
			return false
		}
	}
	if arcs[0] != "0" && arcs[0] != "1" && arcs[0] != "2" {
		return false
	}
	if arcs[0] != "2" && decimalGreaterThan39(arcs[1]) {
		return false
	}
	return true
}

func isCanonicalPositiveDecimal(value string) bool {
	return value != "0" && isCanonicalDecimal(value)
}

// Check ASCII digits directly because unicode.IsDigit accepts non-ASCII digits,
// and integer conversion can overflow valid large OID arcs.
func isCanonicalDecimal(value string) bool {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func decimalGreaterThan39(value string) bool {
	return len(value) > 2 || len(value) == 2 && value > "39"
}
