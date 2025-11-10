package types

import (
	"encoding/json"
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
	internal       any
}

func (m Metadata) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"range":        m.rnge,
		"ref":          m.ref,
		"managed":      m.isManaged,
		"default":      m.isDefault,
		"explicit":     m.isExplicit,
		"unresolvable": m.isUnresolvable,
		"parent":       m.parent,
	})
}

func (m *Metadata) UnmarshalJSON(data []byte) error {
	var keys map[string]any
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	if keys["range"] != nil {
		raw, err := json.Marshal(keys["range"])
		if err != nil {
			return err
		}
		var r Range
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		m.rnge = r
	}
	if keys["ref"] != nil {
		m.ref = keys["ref"].(string)
	}
	if keys["managed"] != nil {
		m.isManaged = keys["managed"].(bool)
	}
	if keys["default"] != nil {
		m.isDefault = keys["default"].(bool)
	}
	if keys["explicit"] != nil {
		m.isExplicit = keys["explicit"].(bool)
	}
	if keys["unresolvable"] != nil {
		m.isUnresolvable = keys["unresolvable"].(bool)
	}
	if keys["parent"] != nil {
		if _, ok := keys["parent"].(map[string]any); ok {
			raw, err := json.Marshal(keys["parent"])
			if err != nil {
				return err
			}
			var parent Metadata
			if err := json.Unmarshal(raw, &parent); err != nil {
				return err
			}
			m.parent = &parent
		}
	}
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

func (m Metadata) WithInternal(internal any) Metadata {
	m.internal = internal
	return m
}

func (m Metadata) Internal() any {
	return m.internal
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

type BaseAttribute struct {
	metadata Metadata
}

func (b BaseAttribute) GetMetadata() Metadata {
	return b.metadata
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
