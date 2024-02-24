package parser

import (
	"strings"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Module struct {
	metadata iacTypes.Metadata

	attrs map[string]*Attribute
}

func (m *Module) toStringMap() map[string]string {
	res := make(map[string]string)
	for k, v := range m.attrs {
		if v.IsString() {
			res[k] = *v.AsString()
		}
	}
	return res
}

func (m *Module) Metadata() iacTypes.Metadata {
	return m.metadata
}

func (m *Module) GetAttr(name string) *Attribute {
	return m.attrs[name]
}

func (m *Module) GetNestedAttr(path string) *Attribute {
	if path == "" {
		return nil
	}

	parts := strings.SplitN(path, ".", 2)
	attr := m.GetAttr(parts[0])
	if attr == nil {
		return nil
	}
	if len(parts) == 1 {
		return attr
	}
	return attr.GetNestedAttr(parts[1])
}

func (m *Module) GetBoolAttr(name string, defValue ...bool) iacTypes.BoolValue {
	def := iacTypes.BoolDefault(firstOrDefault(defValue), m.metadata)
	attr, exists := m.attrs[name]
	if !exists {
		return def
	}
	val := attr.AsBool()
	if val == nil {
		return def
	}

	return iacTypes.Bool(*val, m.metadata)
}

func (m *Module) GetStringAttr(name string, defValue ...string) iacTypes.StringValue {
	def := iacTypes.StringDefault(firstOrDefault(defValue), m.metadata)
	attr, exists := m.attrs[name]
	if !exists {
		return def
	}
	val := attr.AsString()
	if val == nil {
		return def
	}

	return iacTypes.String(*val, m.metadata)
}

func firstOrDefault[T any](a []T) T {
	if len(a) == 0 {
		return *new(T)
	}
	return a[0]
}
