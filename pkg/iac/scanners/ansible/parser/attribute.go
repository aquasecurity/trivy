package parser

import (
	"strings"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

// TODO move this to a separate package, as a similar structure is used in CloudFormation
type Attribute struct {
	metadata iacTypes.Metadata
	val      any
}

func (a *Attribute) Metadata() iacTypes.Metadata {
	return a.metadata
}

func (a *Attribute) IsNil() bool {
	return a == nil || a.val == nil
}

func (a *Attribute) IsMap() bool {
	if a.IsNil() {
		return false
	}
	_, ok := a.val.(map[string]*Node)
	return ok
}

func (a *Attribute) IsList() bool {
	if a.IsNil() {
		return false
	}
	_, ok := a.val.([]*Node)
	return ok
}

func (a *Attribute) IsBool() bool {
	if a.IsNil() {
		return false
	}
	_, ok := a.val.(bool)
	return ok
}

func (a *Attribute) IsString() bool {
	if a.IsNil() {
		return false
	}
	_, ok := a.val.(string)
	return ok
}

func (a *Attribute) ToList() []*Attribute {
	if a.IsNil() {
		return nil
	}
	val, ok := a.val.([]*Node)
	if !ok {
		return nil
	}

	res := make([]*Attribute, 0, len(val))
	for _, el := range val {
		res = append(res, &Attribute{metadata: el.metadata, val: el.val})
	}

	return res
}

func (a *Attribute) ToMap() map[string]*Attribute {
	if a.IsNil() {
		return make(map[string]*Attribute)
	}
	val, ok := a.val.(map[string]*Node)
	if !ok {
		return nil
	}

	res := make(map[string]*Attribute)
	for k, el := range val {
		res[k] = &Attribute{metadata: el.metadata, val: el.val}
	}

	return res
}

func (a *Attribute) GetNestedAttr(path string) *Attribute {
	if path == "" || !a.IsMap() {
		return nil
	}

	parts := strings.SplitN(path, ".", 2)

	attr, exists := a.ToMap()[parts[0]]
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
	if !a.IsBool() {
		return nil
	}

	val, ok := a.val.(bool)
	if !ok {
		return nil
	}
	return &val
}

func (a *Attribute) AsString() *string {
	if !a.IsString() {
		return nil
	}

	val, ok := a.val.(string)
	if !ok {
		return nil
	}
	return &val
}

func (a *Attribute) Value() any {
	if a.IsNil() {
		return nil
	}

	return a.val
}
