package crypto

import (
	stdcrypto "crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// ErrNoCanonicalForm reports a key that cannot be reduced to SubjectPublicKeyInfo, such as
// the absent key of a certificate whose algorithm crypto/x509 does not recognize.
var ErrNoCanonicalForm = errors.New("key has no canonical form")

// DescribeKey describes a key and the algorithm it belongs to. A private key is described
// through its public projection, so it differs from a public key only in its key type.
//
// A key that cannot be encoded is reported with ErrNoCanonicalForm. Any other error means
// the SubjectPublicKeyInfo produced here does not parse back, and the encoder is wrong.
func DescribeKey(
	pub stdcrypto.PublicKey,
	keyType ftypes.CryptoKeyType,
) (key, keyAlgorithm ftypes.CryptoAssetInfo, err error) {
	identity, algorithmOID, err := publicKeyInfo(pub)
	if err != nil {
		return ftypes.CryptoAssetInfo{}, ftypes.CryptoAssetInfo{}, err
	}

	size, curve := keyDetails(pub)
	keyAlgorithm = DescribeAlgorithm(algorithmOID, size, curve)

	key = ftypes.CryptoAssetInfo{
		Kind:     ftypes.CryptoKindKey,
		KeyType:  keyType,
		Identity: identity,
		Name:     keyAlgorithm.Name + " " + string(keyType) + " key",

		Key: &ftypes.CryptoKey{
			Size:  size,
			Curve: curve,
		},
		Relationships: []ftypes.CryptoRelationship{{
			Type:         ftypes.CryptoRelationshipUsedWith,
			RelatedAsset: keyAlgorithm.Descriptor(),
		}},
	}
	return key, keyAlgorithm, nil
}

// DescribeEncryptedKey describes an encrypted private key container. Its algorithm, size
// and curve live inside the encrypted payload and stay unset.
func DescribeEncryptedKey(
	method ftypes.CryptoIdentityMethod,
	canonical []byte,
	format ftypes.CryptoKeyFormat,
) ftypes.CryptoAssetInfo {
	return ftypes.CryptoAssetInfo{
		Kind:     ftypes.CryptoKindKey,
		KeyType:  ftypes.CryptoKeyTypePrivate,
		Identity: ftypes.DigestIdentity(method, canonical),
		// The container states its format, and nothing else about the key is readable
		// without the passphrase.
		Name: "Encrypted " + string(format) + " private key",

		Key: &ftypes.CryptoKey{
			Encrypted: true,
		},
	}
}

// keyDetails reports the size in bits and the curve of a public key.
func keyDetails(pub stdcrypto.PublicKey) (int, string) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen(), ""
	case *dsa.PublicKey:
		return pub.P.BitLen(), ""
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize, pub.Curve.Params().Name
	case ed25519.PublicKey:
		// An Ed25519 key is the raw point, so its length is the key size in bytes.
		return len(pub) * 8, ""
	}
	return 0, ""
}

// publicKeyInfo canonicalizes a key as PKIX SubjectPublicKeyInfo and reports the identity
// it yields together with the OID of its algorithm.
func publicKeyInfo(pub stdcrypto.PublicKey) (ftypes.CryptoIdentity, string, error) {
	der, err := MarshalPublicKey(pub)
	if err != nil {
		return ftypes.CryptoIdentity{}, "", xerrors.Errorf("%w: %s", ErrNoCanonicalForm, err)
	}

	oid, err := subjectPublicKeyOID(der)
	if err != nil {
		return ftypes.CryptoIdentity{}, "", xerrors.Errorf("read the algorithm of the encoded key: %w", err)
	}

	return ftypes.DigestIdentity(ftypes.CryptoMethodSPKISHA256, der), oid, nil
}

// oidDSA identifies a DSA public key, defined by RFC 3279 section 2.3.2.
// See https://datatracker.ietf.org/doc/html/rfc3279#section-2.3.2
var oidDSA = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}

// MarshalPublicKey encodes a public key as PKIX SubjectPublicKeyInfo, the canonical form a
// key is identified by. A DSA key is encoded here, because crypto/x509 parses that form but
// cannot produce it.
func MarshalPublicKey(pub stdcrypto.PublicKey) ([]byte, error) {
	if key, ok := pub.(*dsa.PublicKey); ok {
		return marshalDSAPublicKey(key)
	}
	return x509.MarshalPKIXPublicKey(pub)
}

// marshalDSAPublicKey encodes a DSA public key the way RFC 3279 section 2.3.2 defines it:
// the domain parameters travel in the algorithm identifier, and the public value is a
// DER integer inside the bit string. crypto/x509 parses this form but cannot produce it.
// See https://datatracker.ietf.org/doc/html/rfc3279#section-2.3.2
func marshalDSAPublicKey(pub *dsa.PublicKey) ([]byte, error) {
	parameters, err := asn1.Marshal(struct {
		P, Q, G *big.Int
	}{pub.P, pub.Q, pub.G})
	if err != nil {
		return nil, xerrors.Errorf("marshal DSA parameters: %w", err)
	}

	value, err := asn1.Marshal(pub.Y)
	if err != nil {
		return nil, xerrors.Errorf("marshal DSA public value: %w", err)
	}

	der, err := asn1.Marshal(struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidDSA,
			Parameters: asn1.RawValue{FullBytes: parameters},
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     value,
			BitLength: len(value) * 8,
		},
	})
	if err != nil {
		return nil, xerrors.Errorf("marshal DSA subject public key info: %w", err)
	}
	return der, nil
}

// subjectPublicKeyOID reads the algorithm OID out of SubjectPublicKeyInfo DER. The OID is
// read from the encoding rather than from PublicKeyAlgorithm, which is an enumeration that
// does not carry it.
func subjectPublicKeyOID(der []byte) (string, error) {
	// The key itself follows the algorithm and is left unread, because encoding/asn1
	// tolerates elements of a sequence that the target struct does not declare.
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
	}
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return "", xerrors.Errorf("unmarshal subject public key info: %w", err)
	}
	return info.Algorithm.Algorithm.String(), nil
}
