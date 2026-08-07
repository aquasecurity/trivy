package crypto

import "golang.org/x/xerrors"

// CryptoRelationshipType identifies how two cryptographic assets are related.
type CryptoRelationshipType string

const (
	// CryptoRelationshipContains indicates containment, for example, a certificate contains its public key.
	CryptoRelationshipContains CryptoRelationshipType = "contains"
	// CryptoRelationshipSignedWith indicates signing, for example, a certificate is signed with its signature algorithm.
	CryptoRelationshipSignedWith CryptoRelationshipType = "signed_with"
	// CryptoRelationshipUsedWith indicates use, for example, a key is used with its key algorithm.
	CryptoRelationshipUsedWith CryptoRelationshipType = "used_with"
	// CryptoRelationshipCorrespondsTo indicates correspondence, for example, a private key corresponds to its derived public key.
	CryptoRelationshipCorrespondsTo CryptoRelationshipType = "corresponds_to"
)

// CryptoRelationship links an asset to another asset descriptor.
type CryptoRelationship struct {
	Type         CryptoRelationshipType `json:",omitempty"`
	RelatedAsset CryptoDescriptor       `json:",omitzero"`
}

func (r CryptoRelationship) validate() error {
	switch r.Type {
	case CryptoRelationshipContains, CryptoRelationshipSignedWith, CryptoRelationshipUsedWith, CryptoRelationshipCorrespondsTo:
	default:
		return xerrors.Errorf("unknown relationship type %q", r.Type)
	}
	if err := r.RelatedAsset.Validate(); err != nil {
		return xerrors.Errorf("validate related asset: %w", err)
	}
	return nil
}
