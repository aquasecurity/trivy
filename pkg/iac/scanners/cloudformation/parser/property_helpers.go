package parser

import (
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func firstOrZero[T any](values []T) T {
	if len(values) > 0 {
		return values[0]
	}
	var zero T
	return zero
}

func (p *Property) IsNil() bool {
	return p == nil || p.Value == nil
}

func (p *Property) IsNotNil() bool {
	return !p.IsUnresolved() && !p.IsNil()
}

func (p *Property) Is(t cftypes.CfType) bool {
	if p.IsNil() || p.IsUnresolved() {
		return false
	}
	if p.isFunction() {
		if prop, success := p.resolveValue(); success && prop != p {
			return prop.Is(t)
		}
	}
	return p.Type == t
}

func (p *Property) IsString() bool {
	return p.Is(cftypes.String)
}

func (p *Property) IsNotString() bool {
	return !p.IsUnresolved() && !p.IsString()
}

func (p *Property) IsInt() bool {
	return p.Is(cftypes.Int)
}

func (p *Property) IsNotInt() bool {
	return !p.IsUnresolved() && !p.IsInt()
}

func (p *Property) IsMap() bool {
	if p.IsNil() || p.IsUnresolved() {
		return false
	}
	return p.Type == cftypes.Map
}

func (p *Property) IsNotMap() bool {
	return !p.IsUnresolved() && !p.IsMap()
}

func (p *Property) IsList() bool {
	return p.Is(cftypes.List)
}

func (p *Property) IsNotList() bool {
	return !p.IsUnresolved() && !p.IsList()
}

func (p *Property) IsBool() bool {
	return p.Is(cftypes.Bool)
}

func (p *Property) IsUnresolved() bool {
	return p != nil && p.unresolved
}

func (p *Property) IsNotBool() bool {
	return !p.IsUnresolved() && !p.IsBool()
}

func (p *Property) AsString() string {
	if p.isFunction() {
		if prop, success := p.resolveValue(); success && prop != p {
			return prop.AsString()
		}
		return ""
	}
	if p.IsNil() {
		return ""
	}
	if !p.IsString() {
		return ""
	}

	return p.Value.(string)
}

func (p *Property) AsStringValue(defaultValue ...string) iacTypes.StringValue {
	if p.IsNil() {
		return p.StringDefault(firstOrZero(defaultValue))
	}
	if p.IsUnresolved() {
		return iacTypes.StringUnresolvable(p.Metadata())
	}
	if !p.IsString() {
		return p.StringDefault(firstOrZero(defaultValue))
	}
	return iacTypes.StringExplicit(p.AsString(), p.Metadata())
}

func (p *Property) AsInt() int {
	if p.isFunction() {
		if prop, success := p.resolveValue(); success && prop != p {
			return prop.AsInt()
		}
		return 0
	}
	if p.IsNotInt() {
		if p.isConvertableToInt() {
			return p.convertToInt().AsInt()
		}
		return 0
	}

	return p.Value.(int)
}

func (p *Property) AsIntValue(defaultValue ...int) iacTypes.IntValue {
	if p.IsNil() {
		return p.IntDefault(firstOrZero(defaultValue))
	}
	if p.IsUnresolved() {
		return iacTypes.IntUnresolvable(p.Metadata())
	}
	if !p.IsInt() {
		return p.IntDefault(firstOrZero(defaultValue))
	}
	return iacTypes.IntExplicit(p.AsInt(), p.Metadata())
}

var boolTrueStrings = map[string]struct{}{
	"true": {}, "yes": {}, "1": {},
}

func (p *Property) AsBool() bool {
	if p.isFunction() {
		if prop, success := p.resolveValue(); success && prop != p {
			return prop.AsBool()
		}
		return false
	}
	switch p.Type {
	case cftypes.Bool:
		return p.Value.(bool)
	case cftypes.String:
		_, ok := boolTrueStrings[strings.ToLower(p.AsString())]
		return ok
	case cftypes.Int:
		return p.AsInt() != 0
	}
	return false
}

func (p *Property) AsBoolValue(defaultValue ...bool) iacTypes.BoolValue {
	if p.IsNil() {
		return p.BoolDefault(firstOrZero(defaultValue))
	}
	if p.IsUnresolved() {
		return iacTypes.BoolUnresolvable(p.Metadata())
	}
	return iacTypes.Bool(p.AsBool(), p.Metadata())
}

func (p *Property) AsMap() map[string]*Property {
	val, ok := p.Value.(map[string]*Property)
	if !ok {
		return nil
	}
	return val
}

func (p *Property) AsList() []*Property {
	if p.isFunction() {
		if prop, success := p.resolveValue(); success && prop != p {
			return prop.AsList()
		}
		return []*Property{}
	}

	if list, ok := p.Value.([]*Property); ok {
		return list
	}
	return nil
}

func (p *Property) Len() int {
	return len(p.AsList())
}

func (p *Property) EqualTo(checkValue any, equalityOptions ...EqualityOptions) bool {
	var ignoreCase bool
	for _, option := range equalityOptions {
		if option == IgnoreCase {
			ignoreCase = true
		}
	}

	switch checkerVal := checkValue.(type) {
	case string:
		if p.IsNil() {
			return false
		}

		if p.Type == cftypes.String || p.IsString() {
			if ignoreCase {
				return strings.EqualFold(p.AsString(), checkerVal)
			}
			return p.AsString() == checkerVal
		} else if p.Type == cftypes.Int || p.IsInt() {
			if val, err := strconv.Atoi(checkerVal); err == nil {
				return p.AsInt() == val
			}
		}
		return false
	case bool:
		if p.Type == cftypes.Bool || p.IsBool() {
			return p.AsBool() == checkerVal
		}
	case int:
		if p.Type == cftypes.Int || p.IsInt() {
			return p.AsInt() == checkerVal
		}
	}

	return false

}

func (p *Property) IsTrue() bool {
	if p.IsNil() || !p.IsBool() {
		return false
	}

	return p.AsBool()
}

func (p *Property) IsEmpty() bool {

	if p.IsNil() {
		return true
	}
	if p.IsUnresolved() {
		return false
	}

	switch p.Type {
	case cftypes.String:
		return p.AsString() == ""
	case cftypes.List, cftypes.Map:
		return len(p.AsList()) == 0
	default:
		return false
	}
}

func (p *Property) Contains(checkVal any) bool {
	if p == nil || p.IsNil() {
		return false
	}

	switch p.Type {
	case cftypes.List:
		for _, p := range p.AsList() {
			if p.EqualTo(checkVal) {
				return true
			}
		}
	case cftypes.Map:
		if _, ok := checkVal.(string); !ok {
			return false
		}
		for key := range p.AsMap() {
			if key == checkVal.(string) {
				return true
			}
		}
	case cftypes.String:
		if _, ok := checkVal.(string); !ok {
			return false
		}
		return strings.Contains(p.AsString(), checkVal.(string))
	}
	return false
}
