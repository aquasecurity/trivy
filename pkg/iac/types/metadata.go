package types

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strings"
)

type Metadata struct {
	rnge           Range
	ref            string
	isManaged      bool
	isDefault      bool
	isExplicit     bool
	isUnresolvable bool
	parent         *Metadata
}

// metadataJSON mirrors the unexported fields of [Metadata].
type metadataJSON struct {
	Range        Range     `json:"range"`
	Ref          string    `json:"ref"`
	Managed      bool      `json:"managed"`
	Default      bool      `json:"default"`
	Explicit     bool      `json:"explicit"`
	Unresolvable bool      `json:"unresolvable"`
	Parent       *Metadata `json:"parent"`
}

func (m Metadata) MarshalJSONTo(enc *jsontext.Encoder) error {
	return json.MarshalEncode(enc, metadataJSON{
		Range:        m.rnge,
		Ref:          m.ref,
		Managed:      m.isManaged,
		Default:      m.isDefault,
		Explicit:     m.isExplicit,
		Unresolvable: m.isUnresolvable,
		Parent:       m.parent,
	})
}

func (m *Metadata) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var raw metadataJSON
	if err := json.UnmarshalDecode(dec, &raw); err != nil {
		return err
	}

	m.rnge = raw.Range
	m.ref = raw.Ref
	m.isManaged = raw.Managed
	m.isDefault = raw.Default
	m.isExplicit = raw.Explicit
	m.isUnresolvable = raw.Unresolvable
	m.parent = raw.Parent
	return nil
}

func (m *Metadata) ToRego() any {
	input := map[string]any{
		"filepath":     m.Range().GetLocalFilename(),
		"startline":    m.Range().GetStartLine(),
		"endline":      m.Range().GetEndLine(),
		"sourceprefix": m.Range().GetSourcePrefix(),
		"managed":      m.isManaged,
		"explicit":     m.isExplicit,
		"unresolvable": m.isUnresolvable,
		"fskey":        CreateFSKey(m.Range().GetFS()),
		"resource":     m.Reference(),
	}
	if m.parent != nil {
		input["parent"] = m.parent.ToRego()
	}
	return input
}

func NewMetadata(r Range, ref string) Metadata {
	return Metadata{
		rnge:      r,
		ref:       ref,
		isManaged: true,
	}
}

func NewUnresolvableMetadata(r Range, ref string) Metadata {
	unres := NewMetadata(r, ref)
	unres.isUnresolvable = true
	return unres
}

func NewExplicitMetadata(r Range, ref string) Metadata {
	m := NewMetadata(r, ref)
	m.isExplicit = true
	return m
}

func (m Metadata) WithParent(p Metadata) Metadata {
	m.parent = &p
	return m
}

func (m *Metadata) SetParentPtr(p *Metadata) {
	m.parent = p
}

func (m Metadata) Parent() *Metadata {
	return m.parent
}

func (m Metadata) Root() Metadata {
	meta := &m
	for meta.Parent() != nil {
		meta = meta.Parent()
	}
	return *meta
}

func (m Metadata) IsMultiLine() bool {
	return m.rnge.GetStartLine() < m.rnge.GetEndLine()
}

func NewUnmanagedMetadata() Metadata {
	m := NewMetadata(NewRange("", 0, 0, "", nil), "")
	m.isManaged = false
	return m
}

func NewTestMetadata() Metadata {
	return NewMetadata(NewRange("test.test", 123, 123, "", nil), "")
}

func NewApiMetadata(provider string, parts ...string) Metadata {
	return NewMetadata(NewRange(fmt.Sprintf("/%s/%s", provider, strings.Join(parts, "/")), 0, 0, "", nil), "")
}

func NewRemoteMetadata(id string) Metadata {
	return NewMetadata(NewRange(id, 0, 0, "remote", nil), id)
}

func (m Metadata) IsDefault() bool {
	return m.isDefault
}

func (m Metadata) IsResolvable() bool {
	return !m.isUnresolvable
}

func (m Metadata) IsExplicit() bool {
	return m.isExplicit
}

func (m Metadata) String() string {
	return m.ref
}

func (m Metadata) Reference() string {
	return m.ref
}

func (m Metadata) Range() Range {
	return m.rnge
}

func (m Metadata) IsManaged() bool {
	return m.isManaged
}

func (m Metadata) IsUnmanaged() bool {
	return !m.isManaged
}

func (m Metadata) GetMetadata() Metadata {
	return m
}

func (m Metadata) GetRawValue() any {
	return nil
}

func (m *Metadata) SetReference(ref string) {
	m.ref = ref
}

func (m *Metadata) SetRange(r Range) {
	m.rnge = r
}
