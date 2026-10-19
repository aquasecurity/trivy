package crypto

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// DescribeKey describes a key and the algorithm it belongs to. A private key is described
// through its public projection, so it differs from a public key only in its key type.
// An error means the key cannot be encoded as SubjectPublicKeyInfo.
func DescribeKey(
	pub stdcrypto.PublicKey,
	keyType ftypes.CryptoKeyType,
) (key, keyAlgorithm ftypes.CryptoAssetInfo, err error) {
	identity, algorithmOID, err := publicKeyInfo(pub)
	if err != nil {
		return ftypes.CryptoAssetInfo{}, ftypes.CryptoAssetInfo{}, err
	}

	size, subgroupSize, curve := keyDetails(pub)
	keyAlgorithm = DescribeAlgorithm(algorithmOID, size, subgroupSize, curve)
	return describeKeyAsset(identity, keyAlgorithm, keyType, size, curve), keyAlgorithm, nil
}

// DescribeRawPublicKey describes a key from its SubjectPublicKeyInfo DER without decoding
// the key itself. The algorithm comes from the OID, the curve stays unset, and the size is
// set only when the OID fixes it. The key is identified by the digest of the
// SubjectPublicKeyInfo.
func DescribeRawPublicKey(
	spki []byte,
	keyType ftypes.CryptoKeyType,
) (key, keyAlgorithm ftypes.CryptoAssetInfo, err error) {
	oid, err := ParseSubjectPublicKeyInfo(spki)
	if err != nil {
		return ftypes.CryptoAssetInfo{}, ftypes.CryptoAssetInfo{}, err
	}

	algorithmOID := oid.String()
	identity := ftypes.DigestIdentity(ftypes.CryptoMethodSPKISHA256, spki)
	size := fixedKeySizes[algorithmOID]
	keyAlgorithm = DescribeAlgorithm(algorithmOID, size, 0, "")
	return describeKeyAsset(identity, keyAlgorithm, keyType, size, ""), keyAlgorithm, nil
}

// fixedKeySizes holds the key size in bits for the algorithms whose OID fixes it. The size
// is the length of the encoded key, defined by RFC 8032 as the parameter b for EdDSA and by
// RFC 7748 for X25519 and X448.
// See https://www.rfc-editor.org/rfc/rfc8032#section-5.2
// See https://www.rfc-editor.org/rfc/rfc7748#section-5
var fixedKeySizes = map[string]int{
	"1.3.101.110": 256, // X25519
	"1.3.101.111": 448, // X448
	"1.3.101.113": 456, // Ed448
}

// describeKeyAsset describes a public or private key whose identity is the digest of the
// SubjectPublicKeyInfo of the key or of its public projection.
func describeKeyAsset(
	identity ftypes.CryptoIdentity,
	keyAlgorithm ftypes.CryptoAssetInfo,
	keyType ftypes.CryptoKeyType,
	size int,
	curve string,
) ftypes.CryptoAssetInfo {
	return ftypes.CryptoAssetInfo{
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

// LinkKeyPairs points every private key at the public key derived from it, when both were
// found. A public key states nothing about the existence of a private one, so the
// reference runs in one direction only.
//
// The two halves are told apart by the key type and share an identity, since a key is
// identified by the digest of its SubjectPublicKeyInfo. An encrypted container is left
// alone, because its identity is the digest of the container, which never equals the
// digest of a SubjectPublicKeyInfo.
func LinkKeyPairs(assets []ftypes.CryptoAsset) {
	public := make(map[ftypes.CryptoIdentity]ftypes.CryptoDescriptor)
	for _, asset := range assets {
		if asset.Kind == ftypes.CryptoKindKey && asset.KeyType == ftypes.CryptoKeyTypePublic {
			public[asset.Identity] = asset.Descriptor()
		}
	}
	if len(public) == 0 {
		return
	}

	for i, asset := range assets {
		if asset.Kind != ftypes.CryptoKindKey || asset.KeyType != ftypes.CryptoKeyTypePrivate {
			continue
		}
		descriptor, found := public[asset.Identity]
		if !found {
			continue
		}
		assets[i].Relationships = append(assets[i].Relationships, ftypes.CryptoRelationship{
			Type:         ftypes.CryptoRelationshipCorrespondsTo,
			RelatedAsset: descriptor,
		})
	}
}

// keyDetails reports the size in bits and the curve of a public key, and for DSA the
// subgroup size in bits.
func keyDetails(pub stdcrypto.PublicKey) (size, subgroupSize int, curve string) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen(), 0, ""
	case *dsa.PublicKey:
		// L and N of FIPS 186, the bit lengths of the primes p and q.
		return pub.P.BitLen(), pub.Q.BitLen(), ""
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize, 0, pub.Curve.Params().Name
	case ed25519.PublicKey:
		// An Ed25519 key is the raw point, so its length is the key size in bytes.
		return len(pub) * 8, 0, ""
	case *mldsa.PublicKey:
		// An ML-DSA public key is a fixed-length encoding decided by the parameter set, so its
		// size is the length of that encoding.
		return pub.Parameters().PublicKeySize() * 8, 0, ""
	}
	return 0, 0, ""
}

// publicKeyInfo canonicalizes a key as PKIX SubjectPublicKeyInfo and reports the identity
// it yields together with the OID of its algorithm.
func publicKeyInfo(pub stdcrypto.PublicKey) (ftypes.CryptoIdentity, string, error) {
	der, err := MarshalPublicKey(pub)
	if err != nil {
		return ftypes.CryptoIdentity{}, "", xerrors.Errorf("marshal public key: %w", err)
	}

	// The OID is read from the encoding, because PublicKeyAlgorithm is an enumeration that
	// does not carry it.
	oid, err := ParseSubjectPublicKeyInfo(der)
	if err != nil {
		return ftypes.CryptoIdentity{}, "", xerrors.Errorf("read the algorithm of the encoded key: %w", err)
	}

	return ftypes.DigestIdentity(ftypes.CryptoMethodSPKISHA256, der), oid.String(), nil
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

// ParseSubjectPublicKeyInfo reads the algorithm OID out of SubjectPublicKeyInfo DER. A key
// of an algorithm whose OID fixes the key size is rejected when its length differs.
func ParseSubjectPublicKeyInfo(der []byte) (asn1.ObjectIdentifier, error) {
	var info struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil {
		return nil, xerrors.Errorf("unmarshal subject public key info: %w", err)
	}
	if len(rest) > 0 {
		return nil, xerrors.Errorf("subject public key info is followed by %d bytes", len(rest))
	}

	// The identity is the digest of these bytes, so a key written with extra elements would
	// get another identity than the same key without them. encoding/asn1 skips elements the
	// target struct does not declare, and re-encoding detects them.
	encoded, err := asn1.Marshal(info)
	if err != nil {
		return nil, xerrors.Errorf("marshal subject public key info: %w", err)
	}
	if !bytes.Equal(encoded, der) {
		return nil, xerrors.New("subject public key info does not round-trip")
	}

	oid := info.Algorithm.Algorithm
	if size, ok := fixedKeySizes[oid.String()]; ok && info.SubjectPublicKey.BitLength != size {
		return nil, xerrors.Errorf("%s key is %d bits instead of %d", oid, info.SubjectPublicKey.BitLength, size)
	}
	return oid, nil
}
