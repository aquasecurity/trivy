package types

import (
	"encoding/json"
	"fmt"
	"strings"
)

type MisconfigMetadata struct {
	rnge           Range
	ref            string
	isManaged      bool
	isDefault      bool
	isExplicit     bool
	isUnresolvable bool
	parent         *MisconfigMetadata
	internal       interface{}
}

func (m MisconfigMetadata) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"range":        m.rnge,
		"ref":          m.ref,
		"managed":      m.isManaged,
		"default":      m.isDefault,
		"explicit":     m.isExplicit,
		"unresolvable": m.isUnresolvable,
		"parent":       m.parent,
	})
}

func (m *MisconfigMetadata) UnmarshalJSON(data []byte) error {
	var keys map[string]interface{}
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
		if _, ok := keys["parent"].(map[string]interface{}); ok {
			raw, err := json.Marshal(keys["parent"])
			if err != nil {
				return err
			}
			var parent MisconfigMetadata
			if err := json.Unmarshal(raw, &parent); err != nil {
				return err
			}
			m.parent = &parent
		}
	}
	return nil
}

func (m *MisconfigMetadata) ToRego() interface{} {
	input := map[string]interface{}{
		"filepath":     m.Range().GetLocalFilename(),
		"startline":    m.Range().GetStartLine(),
		"endline":      m.Range().GetEndLine(),
		"sourceprefix": m.Range().GetSourcePrefix(),
		"managed":      m.isManaged,
		"explicit":     m.isExplicit,
		"fskey":        CreateFSKey(m.Range().GetFS()),
		"resource":     m.Reference(),
	}
	if m.parent != nil {
		input["parent"] = m.parent.ToRego()
	}
	return input
}

func NewMisconfigMetadata(r Range, ref string) MisconfigMetadata {
	return MisconfigMetadata{
		rnge:      r,
		ref:       ref,
		isManaged: true,
	}
}

func NewUnresolvableMisconfigMetadata(r Range, ref string) MisconfigMetadata {
	unres := NewMisconfigMetadata(r, ref)
	unres.isUnresolvable = true
	return unres
}

func NewExplicitMisconfigMetadata(r Range, ref string) MisconfigMetadata {
	m := NewMisconfigMetadata(r, ref)
	m.isExplicit = true
	return m
}

func (m MisconfigMetadata) WithParent(p MisconfigMetadata) MisconfigMetadata {
	m.parent = &p
	return m
}

func (m *MisconfigMetadata) SetParentPtr(p *MisconfigMetadata) {
	m.parent = p
}

func (m MisconfigMetadata) Parent() *MisconfigMetadata {
	return m.parent
}

func (m MisconfigMetadata) Root() MisconfigMetadata {
	meta := &m
	for meta.Parent() != nil {
		meta = meta.Parent()
	}
	return *meta
}

func (m MisconfigMetadata) WithInternal(internal interface{}) MisconfigMetadata {
	m.internal = internal
	return m
}

func (m MisconfigMetadata) Internal() interface{} {
	return m.internal
}

func (m MisconfigMetadata) IsMultiLine() bool {
	return m.rnge.GetStartLine() < m.rnge.GetEndLine()
}

func NewUnmanagedMisconfigMetadata() MisconfigMetadata {
	m := NewMisconfigMetadata(NewRange("", 0, 0, "", nil), "")
	m.isManaged = false
	return m
}

func NewTestMisconfigMetadata() MisconfigMetadata {
	return NewMisconfigMetadata(NewRange("test.test", 123, 123, "", nil), "")
}

func NewApiMisconfigMetadata(provider string, parts ...string) MisconfigMetadata {
	return NewMisconfigMetadata(NewRange(fmt.Sprintf("/%s/%s", provider, strings.Join(parts, "/")), 0, 0, "", nil), "")
}

func NewRemoteMisconfigMetadata(id string) MisconfigMetadata {
	return NewMisconfigMetadata(NewRange(id, 0, 0, "remote", nil), id)
}

func (m MisconfigMetadata) IsDefault() bool {
	return m.isDefault
}

func (m MisconfigMetadata) IsResolvable() bool {
	return !m.isUnresolvable
}

func (m MisconfigMetadata) IsExplicit() bool {
	return m.isExplicit
}

func (m MisconfigMetadata) String() string {
	return m.ref
}

func (m MisconfigMetadata) Reference() string {
	return m.ref
}

func (m MisconfigMetadata) Range() Range {
	return m.rnge
}

func (m MisconfigMetadata) IsManaged() bool {
	return m.isManaged
}

func (m MisconfigMetadata) IsUnmanaged() bool {
	return !m.isManaged
}

type BaseAttribute struct {
	misconfigmetadata MisconfigMetadata
}

func (b BaseAttribute) GetMetadata() MisconfigMetadata {
	return b.misconfigmetadata
}

func (m MisconfigMetadata) GetMisconfigMetadata() MisconfigMetadata {
	return m
}

func (m MisconfigMetadata) GetRawValue() interface{} {
	return nil
}

func (m *MisconfigMetadata) SetReference(ref string) {
	m.ref = ref
}

func (m *MisconfigMetadata) SetRange(r Range) {
	m.rnge = r
}
