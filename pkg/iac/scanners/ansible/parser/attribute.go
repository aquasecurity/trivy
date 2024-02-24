package parser

import (
	"io/fs"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

// TODO move this to a separate package, as a similar structure is used in CloudFormation
type Attribute struct {
	inner    attributeInner
	rng      Range
	metadata iacTypes.Metadata
}

type attrKind string

const (
	String attrKind = "string"
	Int    attrKind = "int"
	// Float64 attrKind = "float64"
	Bool attrKind = "bool"
	Map  attrKind = "map"
	List attrKind = "list"
)

type attributeInner struct {
	kind attrKind
	val  any
}

func (a *Attribute) UnmarshalYAML(node *yaml.Node) error {
	a.rng = rangeFromNode(node)

	if node.Content == nil {
		switch node.Tag {
		case "!!int":
			a.inner.kind = Int
			a.inner.val, _ = strconv.Atoi(node.Value)
		case "!!bool":
			a.inner.kind = Bool
			a.inner.val, _ = strconv.ParseBool(node.Value)
		case "!!str", "!!string":
			a.inner.kind = String
			a.inner.val = node.Value
		}
		return nil
	}

	switch node.Tag {
	case "!!map":
		a.rng.startLine--
		var childData map[string]*Attribute
		if err := node.Decode(&childData); err != nil {
			return err
		}
		a.inner.kind = Map
		a.inner.val = childData
		return nil
	case "!!seq":
		a.rng.startLine--
		var childData []*Attribute
		if err := node.Decode(&childData); err != nil {
			return err
		}
		a.inner.kind = List
		a.inner.val = childData
		return nil
	}
	return nil
}

func (a *Attribute) Metadata() iacTypes.Metadata {
	return a.metadata
}

func (a *Attribute) updateMetadata(fsys fs.FS, parent *iacTypes.Metadata, path string) {
	a.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(path, a.rng.startLine, a.rng.endLine, "", fsys),
		"",
	)
	a.metadata.SetParentPtr(parent)

	switch {
	case a.IsMap():
		for _, attr := range a.AsMap() {
			if attr == nil {
				continue
			}
			attr.updateMetadata(fsys, parent, path)
		}
	case a.IsList():
		for _, attr := range a.AsList() {
			if attr == nil {
				continue
			}
			attr.updateMetadata(fsys, parent, path)
		}
	}
}

func (a *Attribute) IsNil() bool {
	return a == nil || a.inner.val == nil
}

func (a *Attribute) IsMap() bool {
	return a.Is(Map)
}

func (a *Attribute) IsList() bool {
	return a.Is(List)
}

func (a *Attribute) IsString() bool {
	return a.Is(String)
}

func (a *Attribute) Is(kind attrKind) bool {
	return !a.IsNil() && a.inner.kind == kind
}

func (a *Attribute) ToList() []*Attribute {
	if a == nil {
		return nil
	}
	val, ok := a.inner.val.([]any)
	if !ok {
		return nil
	}

	res := make([]*Attribute, 0, len(val))
	for _, el := range val {
		attr, ok := el.(*Attribute)
		if !ok {
			continue
		}
		res = append(res, attr)
	}

	return res
}

func (a *Attribute) GetNestedAttr(path string) *Attribute {

	if path == "" || !a.IsMap() {
		return nil
	}

	parts := strings.SplitN(path, ".", 2)

	attr, exists := a.AsMap()[parts[0]]
	if !exists {
		return nil
	}

	if len(parts) == 1 {
		return attr
	}

	return attr.GetNestedAttr(parts[1])
}

func (a *Attribute) GetStringAttr(path string) iacTypes.StringValue {
	def := iacTypes.StringDefault("", a.metadata)
	if a.IsNil() {
		return def
	}

	nested := a.GetNestedAttr(path)
	val := nested.AsString()
	if val == nil {
		return def
	}
	return iacTypes.String(*val, a.metadata)
}

func (a *Attribute) GetBoolAttr(path string) iacTypes.BoolValue {
	def := iacTypes.BoolDefault(false, a.metadata)
	if a.IsNil() {
		return def
	}

	nested := a.GetNestedAttr(path)
	val := nested.AsBool()
	if val == nil {
		return def
	}

	return iacTypes.Bool(*val, iacTypes.Metadata{})
}

func (a *Attribute) AsBool() *bool {
	if !a.Is(Bool) {
		return nil
	}

	val, ok := a.inner.val.(bool)
	if !ok {
		return nil
	}
	return &val
}

func (a *Attribute) AsString() *string {
	if !a.Is(String) {
		return nil
	}

	val, ok := a.inner.val.(string)
	if !ok {
		return nil
	}
	return &val
}

func (a *Attribute) AsMap() map[string]*Attribute {
	if !a.IsMap() {
		return nil
	}

	val, ok := a.inner.val.(map[string]*Attribute)
	if !ok {
		return nil
	}
	return val
}

func (a *Attribute) AsList() []*Attribute {
	if !a.IsList() {
		return nil
	}

	val, ok := a.inner.val.([]*Attribute)
	if !ok {
		return nil
	}
	return val
}

func (a *Attribute) Value() any {
	if a.IsNil() {
		return nil
	}

	return a.inner.val
}
