package parser

import (
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func (p *Property) IsNil() bool {
	return p == nil || p.Inner.Value == nil
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
	return p.Inner.Type == t
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
	return p.Inner.Type == cftypes.Map
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

	return p.Inner.Value.(string)
}

func (p *Property) AsStringValue() iacTypes.StringValue {
	if p.unresolved {
		return iacTypes.StringUnresolvable(p.Metadata())
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

	return p.Inner.Value.(int)
}

func (p *Property) AsIntValue() iacTypes.IntValue {
	if p.unresolved {
		return iacTypes.IntUnresolvable(p.Metadata())
	}
	return iacTypes.IntExplicit(p.AsInt(), p.Metadata())
}

func (p *Property) AsBool() bool {
	if p.isFunction() {
		if prop, success := p.resolveValue(); success && prop != p {
			return prop.AsBool()
		}
		return false
	}
	if !p.IsBool() {
		return false
	}
	return p.Inner.Value.(bool)
}

func (p *Property) AsBoolValue() iacTypes.BoolValue {
	if p.unresolved {
		return iacTypes.BoolUnresolvable(p.Metadata())
	}
	return iacTypes.Bool(p.AsBool(), p.Metadata())
}

func (p *Property) AsMap() map[string]*Property {
	val, ok := p.Inner.Value.(map[string]*Property)
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

	if list, ok := p.Inner.Value.([]*Property); ok {
		return list
	}
	return nil
}

func (p *Property) Len() int {
	return len(p.AsList())
}

func (p *Property) EqualTo(checkValue interface{}, equalityOptions ...EqualityOptions) bool {
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

		if p.Inner.Type == cftypes.String || p.IsString() {
			if ignoreCase {
				return strings.EqualFold(p.AsString(), checkerVal)
			}
			return p.AsString() == checkerVal
		} else if p.Inner.Type == cftypes.Int || p.IsInt() {
			if val, err := strconv.Atoi(checkerVal); err == nil {
				return p.AsInt() == val
			}
		}
		return false
	case bool:
		if p.Inner.Type == cftypes.Bool || p.IsBool() {
			return p.AsBool() == checkerVal
		}
	case int:
		if p.Inner.Type == cftypes.Int || p.IsInt() {
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

	switch p.Inner.Type {
	case cftypes.String:
		return p.AsString() == ""
	case cftypes.List, cftypes.Map:
		return len(p.AsList()) == 0
	default:
		return false
	}
}

func (p *Property) Contains(checkVal interface{}) bool {
	if p == nil || p.IsNil() {
		return false
	}

	switch p.Type() {
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
