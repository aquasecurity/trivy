package name

import (
	"encoding/json"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
)

// Reference wraps name.Reference to support JSON marshaling/unmarshaling
type Reference struct {
	name.Reference
}

// ParseReference parses a string into a Reference
func ParseReference(s string) (Reference, error) {
	if s == "" {
		return Reference{}, nil
	}
	ref, err := name.ParseReference(s)
	if err != nil {
		return Reference{}, xerrors.Errorf("failed to parse reference: %w", err)
	}
	return Reference{Reference: ref}, nil
}

// MarshalJSON implements json.Marshaler
func (r Reference) MarshalJSON() ([]byte, error) {
	if lo.IsNil(r.Reference) {
		return json.Marshal("")
	}
	return json.Marshal(r.Reference.String())
}

// UnmarshalJSON implements json.Unmarshaler
func (r *Reference) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return xerrors.Errorf("failed to unmarshal reference: %w", err)
	}
	if s == "" {
		r.Reference = nil
		return nil
	}
	ref, err := name.ParseReference(s)
	if err != nil {
		return xerrors.Errorf("failed to parse reference: %w", err)
	}
	r.Reference = ref
	return nil
}

// IsZero returns true if the reference is empty (for omitzero support)
func (r Reference) IsZero() bool {
	return lo.IsNil(r.Reference)
}
