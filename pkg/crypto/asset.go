package crypto

import (
	"slices"

	"github.com/samber/lo"
	"golang.org/x/xerrors"
)

// Kind identifies the category of a cryptographic asset.
type Kind string

const (
	// KindCertificate identifies a certificate asset.
	KindCertificate Kind = "certificate"
	// KindKey identifies a cryptographic key asset.
	KindKey Kind = "key"
	// KindAlgorithm identifies a cryptographic algorithm asset.
	KindAlgorithm Kind = "algorithm"
)

// IdentityMethod identifies the canonical method used to identify an asset.
type IdentityMethod string

const (
	// MethodSHA256 identifies KindCertificate assets. The value is the lowercase SHA-256 digest of canonical X.509 DER, and parameters are empty.
	MethodSHA256 IdentityMethod = "sha256"
	// MethodSPKISHA256 identifies KindKey assets with KeyTypePublic or unencrypted KeyTypePrivate. The value is the lowercase SHA-256 digest of SubjectPublicKeyInfo DER, and parameters are empty.
	MethodSPKISHA256 IdentityMethod = "spki-sha256"
	// MethodEncryptedPKCS8SHA256 identifies opaque KindKey assets with KeyTypePrivate. The value is the lowercase SHA-256 digest of encrypted PKCS#8 DER, and parameters are empty.
	MethodEncryptedPKCS8SHA256 IdentityMethod = "encrypted-pkcs8-sha256"
	// MethodOID identifies KindAlgorithm assets. The value is a canonical dotted-decimal OID, and parameters are empty or key-size=<bits> / curve=<name> when needed to distinguish the algorithm asset.
	MethodOID IdentityMethod = "oid"
)

// Identity is the method-specific portion of an Asset's identity; Kind and, for key assets, KeyType complete the identity represented by Descriptor.
type Identity struct {
	Method     IdentityMethod `json:",omitempty"`
	Value      string         `json:",omitempty"`
	Parameters string         `json:",omitempty"`
}

// Asset describes a format-neutral cryptographic asset.
type Asset struct {
	descriptor *Descriptor

	Kind     Kind     `json:",omitempty"`
	KeyType  KeyType  `json:",omitempty"`
	Identity Identity `json:",omitzero"`
	Name     string   `json:",omitempty"`
	FilePath string   `json:",omitempty"`

	// TODO: Replace these fields with fanal/types.Layer after layer provenance
	// moves to a package that crypto can import without an import cycle.
	LayerDigest string `json:",omitempty"`
	LayerDiffID string `json:",omitempty"`

	Certificate   *Certificate   `json:",omitempty"`
	Key           *Key           `json:",omitempty"`
	Algorithm     *Algorithm     `json:",omitempty"`
	Relationships []Relationship `json:",omitempty"`
}

// Descriptor returns the cached comparable identity of the asset. Kind,
// KeyType, and Identity must not change after the first call. FilePath,
// layer fields, details, and relationships remain non-identity fields and may
// be set later.
func (a *Asset) Descriptor() Descriptor {
	if a.descriptor == nil {
		a.descriptor = new(Descriptor{
			Kind:     a.Kind,
			KeyType:  a.KeyType,
			Identity: a.Identity,
		})
	}
	return *a.descriptor
}

// Validate checks the intrinsic asset invariants.
func (a *Asset) Validate() error {
	descriptor := a.Descriptor()
	if err := descriptor.Validate(); err != nil {
		return xerrors.Errorf("validate descriptor: %w", err)
	}

	detailCount := lo.CountBy([]any{a.Certificate, a.Key, a.Algorithm}, lo.IsNotNil)
	if detailCount != 1 {
		return xerrors.Errorf("asset must contain exactly one detail, got %d", detailCount)
	}

	switch a.Kind {
	case KindCertificate:
		if a.Certificate == nil {
			return xerrors.Errorf("asset kind %q requires certificate details", a.Kind)
		}
		if err := a.validateCertificate(); err != nil {
			return xerrors.Errorf("validate certificate: %w", err)
		}
	case KindKey:
		if a.Key == nil {
			return xerrors.Errorf("asset kind %q requires key details", a.Kind)
		}
		if err := a.validateKey(); err != nil {
			return xerrors.Errorf("validate key: %w", err)
		}
	case KindAlgorithm:
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

// Clone returns a deep copy of the asset.
func (a *Asset) Clone() Asset {
	clone := *a
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

func (a *Asset) validateCertificate() error {
	if a.Certificate.Format != CertificateFormatX509 {
		return xerrors.Errorf("unknown certificate format %q", a.Certificate.Format)
	}
	if a.Certificate.MaxPathLen < 0 {
		return xerrors.Errorf("certificate path length must not be negative")
	}
	return nil
}

func (a *Asset) validateKey() error {
	if a.Key.Size < 0 {
		return xerrors.Errorf("key size must not be negative")
	}
	switch a.Key.Format {
	case "", KeyFormatPKCS1, KeyFormatPKCS8, KeyFormatSEC1, KeyFormatPKIX:
	default:
		return xerrors.Errorf("unknown key format %q", a.Key.Format)
	}
	switch a.Key.Encoding {
	case "", EncodingPEM, EncodingDER:
	default:
		return xerrors.Errorf("unknown key encoding %q", a.Key.Encoding)
	}

	encrypted := a.KeyType == KeyTypePrivate && a.Identity.Method == MethodEncryptedPKCS8SHA256
	if a.Key.Encrypted != encrypted {
		return xerrors.Errorf("key encrypted flag does not match identification method %q", a.Identity.Method)
	}
	return nil
}

func (a *Asset) validateAlgorithm() error {
	switch a.Algorithm.Primitive {
	case PrimitiveUnknown, PrimitiveSignature, PrimitivePKE:
	default:
		return xerrors.Errorf("unknown algorithm primitive %q", a.Algorithm.Primitive)
	}
	return nil
}
