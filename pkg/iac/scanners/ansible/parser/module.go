package parser

import (
	"strings"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Module struct {
	metadata iacTypes.Metadata

	// Value for a free-form call, for example, "file.yml" for - include_tasks: file.yml
	freeForm string

	params map[string]*Node
}

func (m *Module) Metadata() iacTypes.Metadata {
	return m.metadata
}

func (m *Module) IsFreeForm() bool {
	return len(m.params) == 0 && m.freeForm != ""
}

func (m *Module) GetAttr(name string) *Attribute {
	node, exists := m.params[name]
	if !exists || node == nil {
		return nil
	}

	return &Attribute{metadata: node.metadata, val: node.val}
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
	attrNode, exists := m.params[name]
	if !exists {
		return def
	}

	switch n := attrNode.val.(type) {
	case *Scalar:
		v, ok := n.Val.(bool)
		if ok {
			return iacTypes.Bool(v, m.metadata)
		}
	}
	return def
}

func (m *Module) GetStringAttr(name string, defValue ...string) iacTypes.StringValue {
	def := iacTypes.StringDefault(firstOrDefault(defValue), m.metadata)
	attrNode, exists := m.params[name]
	if !exists {
		return def
	}

	switch n := attrNode.val.(type) {
	case *Scalar:
		v, ok := n.Val.(string)
		if ok {
			return iacTypes.String(v, m.metadata)
		}
	}

	return def
}

func firstOrDefault[T any](a []T) T {
	if len(a) == 0 {
		return *new(T)
	}
	return a[0]
}
