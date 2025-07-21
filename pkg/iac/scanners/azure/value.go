package azure

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/types"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type EvalContext struct{}

type Kind string

const (
	KindUnresolvable Kind = "unresolvable"
	KindNull         Kind = "null"
	KindBoolean      Kind = "boolean"
	KindString       Kind = "string"
	KindNumber       Kind = "number"
	KindObject       Kind = "object"
	KindArray        Kind = "array"
	KindExpression   Kind = "expression"
)

type Value struct {
	xjson.Location
	metadata *types.Metadata
	rLit     any
	rMap     map[string]Value
	rArr     []Value
	Kind     Kind
	Comments []string
}

var NullValue = Value{
	Kind: KindNull,
}

func NewValue(value any, metadata types.Metadata) Value {

	v := Value{
		metadata: &metadata,
		Location: xjson.Location{
			StartLine: metadata.Range().GetStartLine(),
			EndLine:   metadata.Range().GetEndLine(),
		},
	}

	switch ty := value.(type) {
	case []any:
		v.Kind = KindArray
		for _, child := range ty {
			if internal, ok := child.(Value); ok {
				v.rArr = append(v.rArr, internal)
			} else {
				v.rArr = append(v.rArr, NewValue(child, metadata))
			}
		}
	case []Value:
		v.Kind = KindArray
		v.rArr = append(v.rArr, ty...)

	case map[string]any:
		v.Kind = KindObject
		v.rMap = make(map[string]Value)
		for key, val := range ty {
			if internal, ok := val.(Value); ok {
				v.rMap[key] = internal
			} else {
				v.rMap[key] = NewValue(val, metadata)
			}
		}
	case map[string]Value:
		v.Kind = KindObject
		v.rMap = make(map[string]Value)
		for key, val := range ty {
			v.rMap[key] = val
		}
	case string:
		v.Kind = KindString
		v.rLit = ty
	case int, int64, int32, float32, float64, int8, int16, uint8, uint16, uint32, uint64:
		v.Kind = KindNumber
		v.rLit = ty
	case bool:
		v.Kind = KindBoolean
		v.rLit = ty
	case nil:
		v.Kind = KindNull
		v.rLit = ty
	default:
		v.Kind = KindUnresolvable
		v.rLit = ty
	}

	return v
}

func (v *Value) GetMetadata() types.Metadata {
	return lo.FromPtr(v.metadata)
}

func (v *Value) SetMetadata(m *types.Metadata) {
	v.metadata = m
}

func (v *Value) WithLocation(loc xjson.Location) *Value {
	v.Location = loc
	return v
}

func (n *Value) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	switch k := dec.PeekKind(); k {
	case 't', 'f':
		n.Kind = KindBoolean
		if err := json.UnmarshalDecode(dec, &n.rLit); err != nil {
			return err
		}
	case '"':
		n.Kind = KindString
		if err := json.UnmarshalDecode(dec, &n.rLit); err != nil {
			return err
		}
	case '0':
		n.Kind = KindNumber
		if err := json.UnmarshalDecode(dec, &n.rLit); err != nil {
			return err
		}
		if f, ok := n.rLit.(float64); ok {
			if i := int64(f); float64(i) == f {
				n.rLit = i
			}
		}
	case '[':
		n.Kind = KindArray
		if err := json.UnmarshalDecode(dec, &n.rArr); err != nil {
			return err
		}
	case '{':
		n.Kind = KindObject
		if err := json.UnmarshalDecode(dec, &n.rMap); err != nil {
			return err
		}
	case 'n':
		// TODO: UnmarshalJSONFrom is called only for the root null
		return dec.SkipValue()
	case 0:
		return dec.SkipValue()
	default:
		return fmt.Errorf("unexpected token kind %q at %d", k.String(), dec.InputOffset())
	}
	return nil
}

func (v Value) AsString() string {
	v.Resolve()

	if v.Kind != KindString {
		return ""
	}

	return v.rLit.(string)
}

func (v Value) AsBool() bool {
	v.Resolve()
	if v.Kind != KindBoolean {
		return false
	}
	return v.rLit.(bool)
}

func (v Value) AsInt() int {
	v.Resolve()
	if v.Kind != KindNumber {
		return 0
	}
	return int(v.rLit.(int64))
}

func (v Value) AsFloat() float64 {
	v.Resolve()
	if v.Kind != KindNumber {
		return 0
	}
	return v.rLit.(float64)
}

func (v Value) AsIntValue(defaultValue int, metadata types.Metadata) types.IntValue {
	v.Resolve()
	if v.Kind != KindNumber {
		return types.Int(defaultValue, metadata)
	}
	return types.Int(v.AsInt(), metadata)
}

func (v Value) AsBoolValue(defaultValue bool, metadata types.Metadata) types.BoolValue {
	v.Resolve()
	if v.Kind == KindString {
		possibleValue := strings.ToLower(v.rLit.(string))
		if slices.Contains([]string{
			"true",
			"1",
			"yes",
			"on",
			"enabled",
		}, possibleValue) {
			return types.Bool(true, metadata)
		}
	}

	if v.Kind != KindBoolean {
		return types.Bool(defaultValue, metadata)
	}

	return types.Bool(v.rLit.(bool), v.GetMetadata())
}

func (v Value) EqualTo(value any) bool {
	switch ty := value.(type) {
	case string:
		return v.AsString() == ty
	default:
		panic("not supported")
	}
}

func (v Value) AsStringValue(defaultValue string, metadata types.Metadata) types.StringValue {
	v.Resolve()
	if v.Kind != KindString {
		return types.StringDefault(defaultValue, metadata)
	}
	return types.String(v.rLit.(string), v.GetMetadata())
}

func (v Value) GetMapValue(key string) Value {
	v.Resolve()
	if v.Kind != KindObject {
		return NullValue
	}
	v, exists := v.rMap[key]
	if !exists {
		return NullValue
	}
	return v
}

func (v Value) AsMap() map[string]Value {
	v.Resolve()
	if v.Kind != KindObject {
		return nil
	}
	return v.rMap
}

func (v Value) AsList() []Value {
	v.Resolve()
	if v.Kind != KindArray {
		return nil
	}
	return v.rArr
}

func (v Value) Raw() any {
	switch v.Kind {
	case KindArray:
		// TODO: recursively build raw array
		return nil
	case KindObject:
		// TODO: recursively build raw object
		return nil
	default:
		return v.rLit
	}
}

func (v *Value) Resolve() {
	if v.Kind != KindExpression {
		return
	}
	// if resolver, ok := v.Metadata.Internal().(Resolver); ok {
	// 	*v = resolver.ResolveExpression(*v)
	// }
}

func (v Value) HasKey(key string) bool {
	v.Resolve()
	_, ok := v.rMap[key]
	return ok
}

func (v Value) AsTimeValue(parentMeta types.Metadata) types.TimeValue {
	v.Resolve()

	switch v.Kind {
	case KindString:
		t, err := time.Parse(time.RFC3339, v.rLit.(string))
		if err != nil {
			return types.Time(time.Time{}, parentMeta)
		}
		return types.Time(t, v.GetMetadata())
	case KindNumber:
		var tv int64
		switch vv := v.rLit.(type) {
		case float64:
			tv = int64(vv)
		case int64:
			tv = vv
		}
		return types.Time(time.Unix(tv, 0), v.GetMetadata())
	default:
		return types.Time(time.Time{}, parentMeta)
	}
}

func (v Value) AsStringValuesList(defaultValue string) (stringValues []types.StringValue) {
	v.Resolve()
	if v.Kind != KindArray {
		return
	}
	for _, item := range v.rArr {
		stringValues = append(stringValues, item.AsStringValue(defaultValue, item.GetMetadata()))
	}

	return stringValues
}

func (v Value) IsNull() bool {
	return v.Kind == KindNull
}

func (v Value) Equal(other Value) bool {
	return v.Location == other.Location &&
		v.Kind == other.Kind &&
		slices.Equal(v.Comments, other.Comments) &&
		v.rLit == other.rLit &&
		compareMap(v.rMap, other.rMap) &&
		compareValueSlices(v.rArr, other.rArr) &&
		v.metadata.Equal(other.metadata)
}

func compareValueSlices(a, b []Value) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func compareMap(a, b map[string]Value) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			return false
		}
		if !va.Equal(vb) {
			return false
		}
	}
	return true
}
