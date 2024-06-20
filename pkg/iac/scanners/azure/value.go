package azure

import (
	"slices"
	"strings"
	"time"

	armjson2 "github.com/aquasecurity/trivy/pkg/iac/scanners/azure/arm/parser/armjson"
	"github.com/aquasecurity/trivy/pkg/iac/types"
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
	types.Metadata
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
		Metadata: metadata,
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
	return v.Metadata
}

func (v *Value) UnmarshalJSONWithMetadata(node armjson2.Node) error {

	v.updateValueKind(node)

	v.Metadata = node.Metadata()

	switch node.Kind() {
	case armjson2.KindArray:
		err := v.unmarshallArray(node)
		if err != nil {
			return err
		}
	case armjson2.KindObject:
		err := v.unmarshalObject(node)
		if err != nil {
			return err
		}
	case armjson2.KindString:
		err := v.unmarshalString(node)
		if err != nil {
			return err
		}
	default:
		if err := node.Decode(&v.rLit); err != nil {
			return err
		}
	}

	for _, comment := range node.Comments() {
		var str string
		if err := comment.Decode(&str); err != nil {
			return err
		}
		// remove `\r` from comment when running windows
		str = strings.ReplaceAll(str, "\r", "")

		v.Comments = append(v.Comments, str)
	}
	return nil
}

func (v *Value) unmarshalString(node armjson2.Node) error {
	var str string
	if err := node.Decode(&str); err != nil {
		return err
	}
	if strings.HasPrefix(str, "[") && !strings.HasPrefix(str, "[[") && strings.HasSuffix(str, "]") {
		// function!
		v.Kind = KindExpression
		v.rLit = str[1 : len(str)-1]
	} else {
		v.rLit = str
	}
	return nil
}

func (v *Value) unmarshalObject(node armjson2.Node) error {
	obj := make(map[string]Value)
	for i := 0; i < len(node.Content()); i += 2 {
		var key string
		if err := node.Content()[i].Decode(&key); err != nil {
			return err
		}
		var val Value
		if err := val.UnmarshalJSONWithMetadata(node.Content()[i+1]); err != nil {
			return err
		}
		obj[key] = val
	}
	v.rMap = obj
	return nil
}

func (v *Value) unmarshallArray(node armjson2.Node) error {
	var arr []Value
	for _, child := range node.Content() {
		var val Value
		if err := val.UnmarshalJSONWithMetadata(child); err != nil {
			return err
		}
		arr = append(arr, val)
	}
	v.rArr = arr
	return nil
}

func (v *Value) updateValueKind(node armjson2.Node) {
	switch node.Kind() {
	case armjson2.KindString:
		v.Kind = KindString
	case armjson2.KindNumber:
		v.Kind = KindNumber
	case armjson2.KindBoolean:
		v.Kind = KindBoolean
	case armjson2.KindObject:
		v.Kind = KindObject
	case armjson2.KindNull:
		v.Kind = KindNull
	case armjson2.KindArray:
		v.Kind = KindArray
	default:
		panic(node.Kind())
	}
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
	return types.String(v.rLit.(string), v.Metadata)
}

func (v Value) GetMapValue(key string) Value {
	v.Resolve()
	if v.Kind != KindObject {
		return NullValue
	}
	return v.rMap[key]
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

func (v Value) AsTimeValue(metadata types.Metadata) types.TimeValue {
	v.Resolve()
	if v.Kind != KindString {
		return types.Time(time.Time{}, metadata)
	}
	if v.Kind == KindNumber {
		return types.Time(time.Unix(int64(v.AsFloat()), 0), metadata)
	}
	t, err := time.Parse(time.RFC3339, v.rLit.(string))
	if err != nil {
		return types.Time(time.Time{}, metadata)
	}
	return types.Time(t, metadata)
}

func (v Value) AsStringValuesList(defaultValue string) (stringValues []types.StringValue) {
	v.Resolve()
	if v.Kind != KindArray {
		return
	}
	for _, item := range v.rArr {
		stringValues = append(stringValues, item.AsStringValue(defaultValue, item.Metadata))
	}

	return stringValues
}
