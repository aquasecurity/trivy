package crypto

import "golang.org/x/xerrors"

// RelationshipType identifies how two cryptographic assets are related.
type RelationshipType string

const (
	// RelationshipContains indicates containment, for example, a certificate contains its public key.
	RelationshipContains RelationshipType = "contains"
	// RelationshipSignedWith indicates signing, for example, a certificate is signed with its signature algorithm.
	RelationshipSignedWith RelationshipType = "signed_with"
	// RelationshipUsedWith indicates use, for example, a key is used with its key algorithm.
	RelationshipUsedWith RelationshipType = "used_with"
	// RelationshipCorrespondsTo indicates correspondence, for example, a private key corresponds to its derived public key.
	RelationshipCorrespondsTo RelationshipType = "corresponds_to"
)

// Relationship links an asset to another asset descriptor.
type Relationship struct {
	Type         RelationshipType `json:",omitempty"`
	RelatedAsset Descriptor       `json:",omitzero"`
}

func (r Relationship) validate() error {
	switch r.Type {
	case RelationshipContains, RelationshipSignedWith, RelationshipUsedWith, RelationshipCorrespondsTo:
	default:
		return xerrors.Errorf("unknown relationship type %q", r.Type)
	}
	if err := r.RelatedAsset.Validate(); err != nil {
		return xerrors.Errorf("validate related asset: %w", err)
	}
	return nil
}
