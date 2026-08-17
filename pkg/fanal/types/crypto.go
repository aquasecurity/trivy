package types

import (
	"cmp"
	"slices"

	"github.com/samber/lo"
	"golang.org/x/xerrors"
)

// CryptoKind identifies the category of a cryptographic asset.
type CryptoKind string

const (
	// CryptoKindCertificate identifies a certificate asset.
	CryptoKindCertificate CryptoKind = "certificate"
	// CryptoKindKey identifies a cryptographic key asset.
	CryptoKindKey CryptoKind = "key"
	// CryptoKindAlgorithm identifies a cryptographic algorithm asset.
	CryptoKindAlgorithm CryptoKind = "algorithm"
)

// CryptoIdentityMethod identifies the canonical method used to identify an asset.
type CryptoIdentityMethod string

const (
	// CryptoMethodSHA256 identifies CryptoKindCertificate assets. The value is the lowercase SHA-256 digest of canonical X.509 DER, and parameters are empty.
	CryptoMethodSHA256 CryptoIdentityMethod = "sha256"
	// CryptoMethodSPKISHA256 identifies CryptoKindKey assets with CryptoKeyTypePublic or unencrypted CryptoKeyTypePrivate. The value is the lowercase SHA-256 digest of SubjectPublicKeyInfo DER, and parameters are empty.
	CryptoMethodSPKISHA256 CryptoIdentityMethod = "spki-sha256"
	// CryptoMethodEncryptedPKCS8SHA256 identifies opaque CryptoKindKey assets with CryptoKeyTypePrivate. The value is the lowercase SHA-256 digest of encrypted PKCS#8 DER, and parameters are empty.
	CryptoMethodEncryptedPKCS8SHA256 CryptoIdentityMethod = "encrypted-pkcs8-sha256"
	// CryptoMethodOID identifies CryptoKindAlgorithm assets. The value is a canonical dotted-decimal OID, and parameters are empty or key-size=<bits> / curve=<name> when needed to distinguish the algorithm asset.
	CryptoMethodOID CryptoIdentityMethod = "oid"
)

// CryptoIdentity is the method-specific portion of a CryptoAsset's identity; Kind and, for key assets, KeyType complete the identity represented by CryptoDescriptor.
type CryptoIdentity struct {
	Method     CryptoIdentityMethod `json:",omitempty"`
	Value      string               `json:",omitempty"`
	Parameters string               `json:",omitempty"`
}

// CryptoEncoding identifies the outer encoding of source cryptographic data.
type CryptoEncoding string

const (
	// CryptoEncodingPEM identifies PEM encoding.
	CryptoEncodingPEM CryptoEncoding = "PEM"
	// CryptoEncodingDER identifies DER encoding.
	CryptoEncodingDER CryptoEncoding = "DER"
)

// CryptoAssetInfo describes a format-neutral cryptographic asset. It states what the
// asset is, independently of where it was found: the same asset found in several files
// and layers has one description.
type CryptoAssetInfo struct {
	Kind     CryptoKind     `json:",omitempty"`
	KeyType  CryptoKeyType  `json:",omitempty"`
	Identity CryptoIdentity `json:",omitzero"`
	Name     string         `json:",omitempty"`

	Certificate   *CryptoCertificate   `json:",omitempty"`
	Key           *CryptoKey           `json:",omitempty"`
	Algorithm     *CryptoAlgorithm     `json:",omitempty"`
	Relationships []CryptoRelationship `json:",omitempty"`
}

// CryptoAsset is a cryptographic asset found at a path in a layer.
type CryptoAsset struct {
	CryptoAssetInfo
	FilePath string `json:",omitempty"`
	Layer    Layer  `json:",omitzero"`
}

// Descriptor returns the comparable identity projected from the asset.
func (a CryptoAssetInfo) Descriptor() CryptoDescriptor {
	return CryptoDescriptor{
		Kind:     a.Kind,
		KeyType:  a.KeyType,
		Identity: a.Identity,
	}
}

// Prefer returns whichever of two descriptions of one asset states more about it. Only a
// container of its own states the format and the encoding of a key, so a key described by
// such a container wins over the same key taken from a certificate.
func (a CryptoAssetInfo) Prefer(other CryptoAssetInfo) CryptoAssetInfo {
	if a.Key != nil && other.Key != nil && a.Key.Format == "" && other.Key.Format != "" {
		return other
	}
	return a
}

// Validate checks the intrinsic asset invariants.
func (a CryptoAssetInfo) Validate() error {
	descriptor := a.Descriptor()
	if err := descriptor.Validate(); err != nil {
		return xerrors.Errorf("validate descriptor: %w", err)
	}

	detailCount := lo.CountBy([]any{a.Certificate, a.Key, a.Algorithm}, lo.IsNotNil)
	if detailCount != 1 {
		return xerrors.Errorf("asset must contain exactly one detail, got %d", detailCount)
	}

	switch a.Kind {
	case CryptoKindCertificate:
		if a.Certificate == nil {
			return xerrors.Errorf("asset kind %q requires certificate details", a.Kind)
		}
		if err := a.validateCertificate(); err != nil {
			return xerrors.Errorf("validate certificate: %w", err)
		}
	case CryptoKindKey:
		if a.Key == nil {
			return xerrors.Errorf("asset kind %q requires key details", a.Kind)
		}
		if err := a.validateKey(); err != nil {
			return xerrors.Errorf("validate key: %w", err)
		}
	case CryptoKindAlgorithm:
		if a.Algorithm == nil {
			return xerrors.Errorf("asset kind %q requires algorithm details", a.Kind)
		}
		if err := a.validateAlgorithm(); err != nil {
			return xerrors.Errorf("validate algorithm: %w", err)
		}
	}

	for i, relationship := range a.Relationships {
		if err := relationship.validate(); err != nil {
			return xerrors.Errorf("validate relationship %d: %w", i, err)
		}
		if relationship.RelatedAsset == descriptor {
			return xerrors.Errorf("relationship %d refers to the source asset", i)
		}
	}
	return nil
}

// CompareCryptoAssets orders assets by identity and then by the path they were found at.
func CompareCryptoAssets(a, b CryptoAsset) int {
	return cmp.Or(
		cmp.Compare(a.Kind, b.Kind),
		cmp.Compare(a.KeyType, b.KeyType),
		cmp.Compare(a.Identity.Method, b.Identity.Method),
		cmp.Compare(a.Identity.Value, b.Identity.Value),
		cmp.Compare(a.Identity.Parameters, b.Identity.Parameters),
		cmp.Compare(a.FilePath, b.FilePath),
	)
}

// DedupeCryptoAssets collapses assets that share an identity, keeping the first
// description of each and preferring the one that states more.
func DedupeCryptoAssets(assets []CryptoAssetInfo) []CryptoAssetInfo {
	// The slice keeps the order the assets were described in; the map holds their positions.
	deduped := make([]CryptoAssetInfo, 0, len(assets))
	indexes := make(map[CryptoDescriptor]int, len(assets))
	for _, asset := range assets {
		descriptor := asset.Descriptor()
		index, seen := indexes[descriptor]
		if !seen {
			indexes[descriptor] = len(deduped)
			deduped = append(deduped, asset)
			continue
		}
		deduped[index] = deduped[index].Prefer(asset)
	}
	return deduped
}

// Clone returns a deep copy of the asset.
func (a CryptoAsset) Clone() CryptoAsset {
	a.CryptoAssetInfo = a.CryptoAssetInfo.Clone()
	return a
}

// Clone returns a deep copy of the description.
func (a CryptoAssetInfo) Clone() CryptoAssetInfo {
	clone := a
	clone.Relationships = slices.Clone(a.Relationships)
	if a.Certificate != nil {
		clone.Certificate = new(*a.Certificate)
		clone.Certificate.KeyUsage = slices.Clone(a.Certificate.KeyUsage)
		clone.Certificate.ExtendedKeyUsage = slices.Clone(a.Certificate.ExtendedKeyUsage)
		clone.Certificate.DNSNames = slices.Clone(a.Certificate.DNSNames)
		clone.Certificate.EmailAddresses = slices.Clone(a.Certificate.EmailAddresses)
		clone.Certificate.IPAddresses = slices.Clone(a.Certificate.IPAddresses)
		clone.Certificate.URIs = slices.Clone(a.Certificate.URIs)
	}
	if a.Key != nil {
		clone.Key = new(*a.Key)
	}
	if a.Algorithm != nil {
		clone.Algorithm = new(*a.Algorithm)
	}
	return clone
}

func (a CryptoAssetInfo) validateCertificate() error {
	if a.Certificate.Format != CryptoCertificateFormatX509 {
		return xerrors.Errorf("unknown certificate format %q", a.Certificate.Format)
	}
	switch a.Certificate.Encoding {
	case "", CryptoEncodingPEM, CryptoEncodingDER:
	default:
		return xerrors.Errorf("unknown certificate encoding %q", a.Certificate.Encoding)
	}
	if a.Certificate.MaxPathLen < 0 {
		return xerrors.Errorf("certificate path length must not be negative")
	}
	if a.Certificate.MaxPathLen != 0 && a.Certificate.MaxPathLenZero {
		return xerrors.Errorf("certificate path length zero flag requires zero path length")
	}
	return nil
}

func (a CryptoAssetInfo) validateKey() error {
	if a.Key.Size < 0 {
		return xerrors.Errorf("key size must not be negative")
	}
	switch a.Key.Format {
	case "", CryptoKeyFormatPKCS1, CryptoKeyFormatPKCS8, CryptoKeyFormatSEC1, CryptoKeyFormatPKIX:
	default:
		return xerrors.Errorf("unknown key format %q", a.Key.Format)
	}
	switch a.Key.Encoding {
	case "", CryptoEncodingPEM, CryptoEncodingDER:
	default:
		return xerrors.Errorf("unknown key encoding %q", a.Key.Encoding)
	}

	encrypted := a.KeyType == CryptoKeyTypePrivate && a.Identity.Method == CryptoMethodEncryptedPKCS8SHA256
	if a.Key.Encrypted != encrypted {
		return xerrors.Errorf("key encrypted flag does not match identification method %q", a.Identity.Method)
	}
	return nil
}

func (a CryptoAssetInfo) validateAlgorithm() error {
	switch a.Algorithm.Primitive {
	case CryptoPrimitiveUnknown, CryptoPrimitiveSignature, CryptoPrimitivePKE:
	default:
		return xerrors.Errorf("unknown algorithm primitive %q", a.Algorithm.Primitive)
	}
	return nil
}
