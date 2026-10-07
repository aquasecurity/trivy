package types

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/xerrors"
)

// CryptoDescriptor is the comparable canonical identity of an asset.
type CryptoDescriptor struct {
	Kind     CryptoKind     `json:",omitempty"`
	KeyType  CryptoKeyType  `json:",omitempty"`
	Identity CryptoIdentity `json:",omitzero"`
}

// String returns the canonical encoded descriptor.
func (d CryptoDescriptor) String() string {
	segments := []string{string(d.Kind)}
	if d.Kind == CryptoKindKey {
		segments = append(segments, string(d.KeyType))
	}
	// QueryEscape uses the standard library's query-component encoding for
	// variable segments. It escapes RFC 3986 reserved characters, including the
	// descriptor's colon delimiter, and represents spaces as '+'.
	segments = append(segments, string(d.Identity.Method), url.QueryEscape(d.Identity.Value))
	// Parameters distinguish algorithm assets that share an OID but use different
	// key sizes, subgroup sizes or curves.
	if d.Identity.Parameters != "" {
		segments = append(segments, url.QueryEscape(d.Identity.Parameters))
	}
	return strings.Join(segments, ":")
}

// MarshalJSON validates and encodes the descriptor as its canonical string.
func (d CryptoDescriptor) MarshalJSON() ([]byte, error) {
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
func (d *CryptoDescriptor) UnmarshalJSON(data []byte) error {
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
func (d CryptoDescriptor) Validate() error {
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

func (d CryptoDescriptor) validateKindKeyTypeMethod() error {
	switch d.Kind {
	case CryptoKindCertificate:
		if d.KeyType != "" {
			return xerrors.Errorf("certificate descriptor must not contain key type %q", d.KeyType)
		}
		if d.Identity.Method != CryptoMethodSHA256 {
			return xerrors.Errorf("certificate descriptor requires identification method %q", CryptoMethodSHA256)
		}
	case CryptoKindKey:
		switch d.KeyType {
		case CryptoKeyTypePublic:
			if d.Identity.Method != CryptoMethodSPKISHA256 {
				return xerrors.Errorf("public key descriptor requires identification method %q", CryptoMethodSPKISHA256)
			}
		case CryptoKeyTypePrivate:
			if d.Identity.Method != CryptoMethodSPKISHA256 &&
				d.Identity.Method != CryptoMethodEncryptedPKCS8SHA256 &&
				d.Identity.Method != CryptoMethodEncryptedRFC1423SHA256 {
				return xerrors.Errorf("private key descriptor has unknown identification method %q", d.Identity.Method)
			}
		default:
			return xerrors.Errorf("unknown key type %q", d.KeyType)
		}
	case CryptoKindAlgorithm:
		if d.KeyType != "" {
			return xerrors.Errorf("algorithm descriptor must not contain key type %q", d.KeyType)
		}
		if d.Identity.Method != CryptoMethodOID {
			return xerrors.Errorf("algorithm descriptor requires identification method %q", CryptoMethodOID)
		}
	default:
		return xerrors.Errorf("unknown asset kind %q", d.Kind)
	}
	return nil
}

func (d CryptoDescriptor) validateIdentityValue() error {
	switch d.Identity.Method {
	case CryptoMethodSHA256, CryptoMethodSPKISHA256, CryptoMethodEncryptedPKCS8SHA256, CryptoMethodEncryptedRFC1423SHA256:
		if !isLowerSHA256(d.Identity.Value) {
			return xerrors.Errorf("identification value must be 64 lowercase hexadecimal characters")
		}
	case CryptoMethodOID:
		if !isCanonicalOID(d.Identity.Value) {
			return xerrors.Errorf("identification value must be a canonical OID")
		}
	}
	return nil
}

func (d CryptoDescriptor) validateParameters() error {
	if d.Identity.Parameters == "" {
		return nil
	}
	if d.Kind != CryptoKindAlgorithm || d.Identity.Method != CryptoMethodOID {
		return xerrors.Errorf("parameters are only valid for OID algorithm descriptors")
	}
	// Validate the algorithm parameters.
	if _, err := d.Identity.AlgorithmParameters(); err != nil {
		return xerrors.Errorf("validate algorithm parameters: %w", err)
	}
	return nil
}

func parseDescriptor(s string) (CryptoDescriptor, error) {
	segments := strings.Split(s, ":")
	var descriptor CryptoDescriptor
	var valueSegment string
	var parametersSegment string

	switch CryptoKind(segments[0]) {
	case CryptoKindCertificate:
		if len(segments) != 3 {
			return CryptoDescriptor{}, xerrors.Errorf("certificate descriptor must contain 3 segments")
		}
		descriptor.Kind = CryptoKindCertificate
		descriptor.Identity.Method = CryptoIdentityMethod(segments[1])
		valueSegment = segments[2]
	case CryptoKindKey:
		if len(segments) != 4 {
			return CryptoDescriptor{}, xerrors.Errorf("key descriptor must contain 4 segments")
		}
		descriptor.Kind = CryptoKindKey
		descriptor.KeyType = CryptoKeyType(segments[1])
		descriptor.Identity.Method = CryptoIdentityMethod(segments[2])
		valueSegment = segments[3]
	case CryptoKindAlgorithm:
		if len(segments) != 3 && len(segments) != 4 {
			return CryptoDescriptor{}, xerrors.Errorf("algorithm descriptor must contain 3 or 4 segments")
		}
		descriptor.Kind = CryptoKindAlgorithm
		descriptor.Identity.Method = CryptoIdentityMethod(segments[1])
		valueSegment = segments[2]
		if len(segments) == 4 {
			parametersSegment = segments[3]
			if parametersSegment == "" {
				return CryptoDescriptor{}, xerrors.Errorf("algorithm descriptor parameters must not be empty")
			}
		}
	default:
		return CryptoDescriptor{}, xerrors.Errorf("unknown descriptor kind %q", segments[0])
	}

	value, err := url.QueryUnescape(valueSegment)
	if err != nil {
		return CryptoDescriptor{}, xerrors.Errorf("decode identification value: %w", err)
	}
	descriptor.Identity.Value = value
	if len(segments) == 4 && descriptor.Kind == CryptoKindAlgorithm {
		parameters, err := url.QueryUnescape(parametersSegment)
		if err != nil {
			return CryptoDescriptor{}, xerrors.Errorf("decode identification parameters: %w", err)
		}
		descriptor.Identity.Parameters = parameters
	}

	if err := descriptor.Validate(); err != nil {
		return CryptoDescriptor{}, xerrors.Errorf("validate descriptor: %w", err)
	}
	return descriptor, nil
}

// CryptoAlgorithmParameterName names a property that distinguishes algorithm assets sharing
// one OID.
type CryptoAlgorithmParameterName string

const (
	// CryptoParameterKeySize distinguishes algorithm assets by key size in bits. For DSA it
	// is L, the bit length of the prime p.
	CryptoParameterKeySize CryptoAlgorithmParameterName = "key-size"
	// CryptoParameterSubgroupSize distinguishes DSA algorithm assets by N, the bit length of
	// the prime q, which FIPS 186 pairs with L to name a parameter set.
	CryptoParameterSubgroupSize CryptoAlgorithmParameterName = "subgroup-size"
	// CryptoParameterCurve distinguishes algorithm assets by curve name.
	CryptoParameterCurve CryptoAlgorithmParameterName = "curve"
)

// CryptoAlgorithmParameters are the key properties that distinguish algorithm assets
// sharing one OID. A zero field is not stated.
type CryptoAlgorithmParameters struct {
	KeySize      int
	SubgroupSize int
	Curve        string
}

// String encodes the parameters in their canonical form: comma-separated name=value pairs
// in the order key-size, subgroup-size, curve, with unstated parameters left out.
func (p CryptoAlgorithmParameters) String() string {
	var pairs []string
	if p.KeySize > 0 {
		pairs = append(pairs, string(CryptoParameterKeySize)+"="+strconv.Itoa(p.KeySize))
	}
	if p.SubgroupSize > 0 {
		pairs = append(pairs, string(CryptoParameterSubgroupSize)+"="+strconv.Itoa(p.SubgroupSize))
	}
	if p.Curve != "" {
		pairs = append(pairs, string(CryptoParameterCurve)+"="+p.Curve)
	}
	return strings.Join(pairs, ",")
}

// AlgorithmParameters decodes the parameters of an algorithm identity. It accepts only the
// canonical form String produces, in which a subgroup size comes with a key size and a
// curve stands alone.
func (i CryptoIdentity) AlgorithmParameters() (CryptoAlgorithmParameters, error) {
	var params CryptoAlgorithmParameters
	if i.Parameters == "" {
		return params, nil
	}

	for pair := range strings.SplitSeq(i.Parameters, ",") {
		name, value, found := strings.Cut(pair, "=")
		if !found {
			return CryptoAlgorithmParameters{}, xerrors.Errorf("unknown algorithm parameter %q", pair)
		}

		switch CryptoAlgorithmParameterName(name) {
		case CryptoParameterKeySize:
			size, ok := parseBitLength(value)
			if !ok {
				return CryptoAlgorithmParameters{}, xerrors.Errorf("key size parameter must be a canonical positive decimal")
			}
			params.KeySize = size
		case CryptoParameterSubgroupSize:
			size, ok := parseBitLength(value)
			if !ok {
				return CryptoAlgorithmParameters{}, xerrors.Errorf("subgroup size parameter must be a canonical positive decimal")
			}
			params.SubgroupSize = size
		case CryptoParameterCurve:
			if value == "" {
				return CryptoAlgorithmParameters{}, xerrors.Errorf("curve parameter must not be empty")
			}
			params.Curve = value
		default:
			return CryptoAlgorithmParameters{}, xerrors.Errorf("unknown algorithm parameter %q", pair)
		}
	}

	if params.SubgroupSize > 0 && params.KeySize == 0 {
		return CryptoAlgorithmParameters{}, xerrors.Errorf("subgroup size parameter requires a key size")
	}
	if params.Curve != "" && params.KeySize > 0 {
		return CryptoAlgorithmParameters{}, xerrors.Errorf("curve parameter must not be combined with sizes")
	}
	// Re-encoding rejects repeated parameters and any order other than the canonical one.
	if params.String() != i.Parameters {
		return CryptoAlgorithmParameters{}, xerrors.Errorf("algorithm parameters %q are not canonical", i.Parameters)
	}
	return params, nil
}

// parseBitLength decodes a bit length written as a canonical positive decimal that fits
// an int.
func parseBitLength(value string) (int, bool) {
	if !isCanonicalPositiveDecimal(value) {
		return 0, false
	}
	size, err := strconv.Atoi(value)
	return size, err == nil
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
