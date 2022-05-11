// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package types declares data types for Rego values and helper functions to
// operate on these types.
package types

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/util"
)

// Sprint returns the string representation of the type.
func Sprint(x Type) string {
	if x == nil {
		return "???"
	}
	return x.String()
}

// Type represents a type of a term in the language.
type Type interface {
	String() string
	typeMarker() string
	json.Marshaler
}

func (Null) typeMarker() string     { return typeNull }
func (Boolean) typeMarker() string  { return typeBoolean }
func (Number) typeMarker() string   { return typeNumber }
func (String) typeMarker() string   { return typeString }
func (*Array) typeMarker() string   { return typeArray }
func (*Object) typeMarker() string  { return typeObject }
func (*Set) typeMarker() string     { return typeSet }
func (Any) typeMarker() string      { return typeAny }
func (Function) typeMarker() string { return typeFunction }

// Null represents the null type.
type Null struct{}

// NewNull returns a new Null type.
func NewNull() Null {
	return Null{}
}

// MarshalJSON returns the JSON encoding of t.
func (t Null) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type": t.typeMarker(),
	})
}

func (t Null) String() string {
	return typeNull
}

// Boolean represents the boolean type.
type Boolean struct{}

// B represents an instance of the boolean type.
var B = NewBoolean()

// NewBoolean returns a new Boolean type.
func NewBoolean() Boolean {
	return Boolean{}
}

// MarshalJSON returns the JSON encoding of t.
func (t Boolean) MarshalJSON() ([]byte, error) {
	repr := map[string]interface{}{
		"type": t.typeMarker(),
	}
	return json.Marshal(repr)
}

func (t Boolean) String() string {
	return t.typeMarker()
}

// String represents the string type.
type String struct{}

// S represents an instance of the string type.
var S = NewString()

// NewString returns a new String type.
func NewString() String {
	return String{}
}

// MarshalJSON returns the JSON encoding of t.
func (t String) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type": t.typeMarker(),
	})
}

func (t String) String() string {
	return typeString
}

// Number represents the number type.
type Number struct{}

// N represents an instance of the number type.
var N = NewNumber()

// NewNumber returns a new Number type.
func NewNumber() Number {
	return Number{}
}

// MarshalJSON returns the JSON encoding of t.
func (t Number) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type": t.typeMarker(),
	})
}

func (Number) String() string {
	return typeNumber
}

// Array represents the array type.
type Array struct {
	static  []Type // static items
	dynamic Type   // dynamic items
}

// NewArray returns a new Array type.
func NewArray(static []Type, dynamic Type) *Array {
	return &Array{
		static:  static,
		dynamic: dynamic,
	}
}

// MarshalJSON returns the JSON encoding of t.
func (t *Array) MarshalJSON() ([]byte, error) {
	repr := map[string]interface{}{
		"type": t.typeMarker(),
	}
	if len(t.static) != 0 {
		repr["static"] = t.static
	}
	if t.dynamic != nil {
		repr["dynamic"] = t.dynamic
	}
	return json.Marshal(repr)
}

func (t *Array) String() string {
	prefix := "array"
	buf := []string{}
	for _, tpe := range t.static {
		buf = append(buf, Sprint(tpe))
	}
	var repr = prefix
	if len(buf) > 0 {
		repr += "<" + strings.Join(buf, ", ") + ">"
	}
	if t.dynamic != nil {
		repr += "[" + t.dynamic.String() + "]"
	}
	return repr
}

// Dynamic returns the type of the array's dynamic elements.
func (t *Array) Dynamic() Type {
	return t.dynamic
}

// Len returns the number of static array elements.
func (t *Array) Len() int {
	return len(t.static)
}

// Select returns the type of element at the zero-based pos.
func (t *Array) Select(pos int) Type {
	if pos >= 0 {
		if len(t.static) > pos {
			return t.static[pos]
		}
		if t.dynamic != nil {
			return t.dynamic
		}
	}
	return nil
}

// Set represents the set type.
type Set struct {
	of Type
}

// NewSet returns a new Set type.
func NewSet(of Type) *Set {
	return &Set{
		of: of,
	}
}

// MarshalJSON returns the JSON encoding of t.
func (t *Set) MarshalJSON() ([]byte, error) {
	repr := map[string]interface{}{
		"type": t.typeMarker(),
	}
	if t.of != nil {
		repr["of"] = t.of
	}
	return json.Marshal(repr)
}

func (t *Set) String() string {
	prefix := typeSet
	return prefix + "[" + Sprint(t.of) + "]"
}

// StaticProperty represents a static object property.
type StaticProperty struct {
	Key   interface{}
	Value Type
}

// NewStaticProperty returns a new StaticProperty object.
func NewStaticProperty(key interface{}, value Type) *StaticProperty {
	return &StaticProperty{
		Key:   key,
		Value: value,
	}
}

// MarshalJSON returns the JSON encoding of p.
func (p *StaticProperty) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"key":   p.Key,
		"value": p.Value,
	})
}

// DynamicProperty represents a dynamic object property.
type DynamicProperty struct {
	Key   Type
	Value Type
}

// NewDynamicProperty returns a new DynamicProperty object.
func NewDynamicProperty(key, value Type) *DynamicProperty {
	return &DynamicProperty{
		Key:   key,
		Value: value,
	}
}

// MarshalJSON returns the JSON encoding of p.
func (p *DynamicProperty) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"key":   p.Key,
		"value": p.Value,
	})
}

func (p *DynamicProperty) String() string {
	return fmt.Sprintf("%s: %s", Sprint(p.Key), Sprint(p.Value))
}

// Object represents the object type.
type Object struct {
	static  []*StaticProperty // constant properties
	dynamic *DynamicProperty  // dynamic properties
}

// NewObject returns a new Object type.
func NewObject(static []*StaticProperty, dynamic *DynamicProperty) *Object {
	sort.Slice(static, func(i, j int) bool {
		cmp := util.Compare(static[i].Key, static[j].Key)
		return cmp == -1
	})
	return &Object{
		static:  static,
		dynamic: dynamic,
	}
}

func (t *Object) String() string {
	prefix := "object"
	buf := make([]string, 0, len(t.static))
	for _, p := range t.static {
		buf = append(buf, fmt.Sprintf("%v: %v", p.Key, Sprint(p.Value)))
	}
	var repr = prefix
	if len(buf) > 0 {
		repr += "<" + strings.Join(buf, ", ") + ">"
	}
	if t.dynamic != nil {
		repr += "[" + t.dynamic.String() + "]"
	}
	return repr
}

// DynamicValue returns the type of the object's dynamic elements.
func (t *Object) DynamicValue() Type {
	if t.dynamic == nil {
		return nil
	}
	return t.dynamic.Value
}

// DynamicProperties returns the type of the object's dynamic elements.
func (t *Object) DynamicProperties() *DynamicProperty {
	return t.dynamic
}

// StaticProperties returns the type of the object's static elements.
func (t *Object) StaticProperties() []*StaticProperty {
	return t.static
}

// Keys returns the keys of the object's static elements.
func (t *Object) Keys() []interface{} {
	sl := make([]interface{}, 0, len(t.static))
	for _, p := range t.static {
		sl = append(sl, p.Key)
	}
	return sl
}

// MarshalJSON returns the JSON encoding of t.
func (t *Object) MarshalJSON() ([]byte, error) {
	repr := map[string]interface{}{
		"type": t.typeMarker(),
	}
	if len(t.static) != 0 {
		repr["static"] = t.static
	}
	if t.dynamic != nil {
		repr["dynamic"] = t.dynamic
	}
	return json.Marshal(repr)
}

// Select returns the type of the named property.
func (t *Object) Select(name interface{}) Type {

	pos := sort.Search(len(t.static), func(x int) bool {
		return util.Compare(t.static[x].Key, name) >= 0
	})

	if pos < len(t.static) && util.Compare(t.static[pos].Key, name) == 0 {
		return t.static[pos].Value
	}

	if t.dynamic != nil {
		if Contains(t.dynamic.Key, TypeOf(name)) {
			return t.dynamic.Value
		}
	}

	return nil
}

// Any represents a dynamic type.
type Any []Type

// A represents the superset of all types.
var A = NewAny()

// NewAny returns a new Any type.
func NewAny(of ...Type) Any {
	sl := make(Any, len(of))
	for i := range sl {
		sl[i] = of[i]
	}
	sort.Sort(typeSlice(sl))
	return sl
}

// Contains returns true if t is a superset of other.
func (t Any) Contains(other Type) bool {
	if _, ok := other.(*Function); ok {
		return false
	}
	for i := range t {
		if Compare(t[i], other) == 0 {
			return true
		}
	}
	return len(t) == 0
}

// MarshalJSON returns the JSON encoding of t.
func (t Any) MarshalJSON() ([]byte, error) {
	data := map[string]interface{}{
		"type": t.typeMarker(),
	}
	if len(t) != 0 {
		data["of"] = []Type(t)
	}
	return json.Marshal(data)
}

// Merge return a new Any type that is the superset of t and other.
func (t Any) Merge(other Type) Any {
	if otherAny, ok := other.(Any); ok {
		return t.Union(otherAny)
	}
	if t.Contains(other) {
		return t
	}
	cpy := make(Any, len(t)+1)
	idx := sort.Search(len(t), func(i int) bool {
		return Compare(t[i], other) >= 0
	})
	copy(cpy, t[:idx])
	cpy[idx] = other
	copy(cpy[idx+1:], t[idx:])
	return cpy
}

// Union returns a new Any type that is the union of the two Any types.
func (t Any) Union(other Any) Any {
	if len(t) == 0 {
		return t
	}
	if len(other) == 0 {
		return other
	}
	cpy := make(Any, len(t))
	for i := range cpy {
		cpy[i] = t[i]
	}
	for i := range other {
		if !cpy.Contains(other[i]) {
			cpy = append(cpy, other[i])
		}
	}
	sort.Sort(typeSlice(cpy))
	return cpy
}

func (t Any) String() string {
	prefix := "any"
	if len(t) == 0 {
		return prefix
	}
	buf := make([]string, len(t))
	for i := range t {
		buf[i] = Sprint(t[i])
	}
	return prefix + "<" + strings.Join(buf, ", ") + ">"
}

// Function represents a function type.
type Function struct {
	args     []Type
	result   Type
	variadic Type
}

// Args returns an argument list.
func Args(x ...Type) []Type {
	return x
}

// Void returns true if the function has no return value. This function returns
// false if x is not a function.
func Void(x Type) bool {
	f, ok := x.(*Function)
	return ok && f.Result() == nil
}

// Arity returns the number of arguments in the function signature or zero if x
// is not a function. If the type is unknown, this function returns -1.
func Arity(x Type) int {
	if x == nil {
		return -1
	}
	f, ok := x.(*Function)
	if !ok {
		return 0
	}
	return len(f.FuncArgs().Args)
}

// NewFunction returns a new Function object where xs[:len(xs)-1] are arguments
// and xs[len(xs)-1] is the result type.
func NewFunction(args []Type, result Type) *Function {
	return &Function{
		args:   args,
		result: result,
	}
}

// NewVariadicFunction returns a new Function object. This function sets the
// variadic bit on the signature. Non-void variadic functions are not currently
// supported.
func NewVariadicFunction(args []Type, varargs Type, result Type) *Function {
	if result != nil {
		panic("illegal value: non-void variadic functions not supported")
	}
	return &Function{
		args:     args,
		variadic: varargs,
		result:   nil,
	}
}

// FuncArgs returns the function's arguments.
func (t *Function) FuncArgs() FuncArgs {
	return FuncArgs{Args: t.Args(), Variadic: t.variadic}
}

// Args returns the function's arguments as a slice, ignoring variadic arguments.
// Deprecated: Use FuncArgs instead.
func (t *Function) Args() []Type {
	cpy := make([]Type, len(t.args))
	copy(cpy, t.args)
	return cpy
}

// Result returns the function's result type.
func (t *Function) Result() Type {
	return t.result
}

func (t *Function) String() string {
	return fmt.Sprintf("%v => %v", t.FuncArgs(), Sprint(t.Result()))
}

// MarshalJSON returns the JSON encoding of t.
func (t *Function) MarshalJSON() ([]byte, error) {
	repr := map[string]interface{}{
		"type": t.typeMarker(),
	}
	if len(t.args) > 0 {
		repr["args"] = t.args
	}
	if t.result != nil {
		repr["result"] = t.result
	}
	if t.variadic != nil {
		repr["variadic"] = t.variadic
	}
	return json.Marshal(repr)
}

// UnmarshalJSON decodes the JSON serialized function declaration.
func (t *Function) UnmarshalJSON(bs []byte) error {

	tpe, err := Unmarshal(bs)
	if err != nil {
		return err
	}

	f, ok := tpe.(*Function)
	if !ok {
		return fmt.Errorf("invalid type")
	}

	*t = *f
	return nil
}

// Union returns a new function represnting the union of t and other. Functions
// must have the same arity to be unioned.
func (t *Function) Union(other *Function) *Function {
	if other == nil {
		return t
	} else if t == nil {
		return other
	}

	a := t.Args()
	b := other.Args()
	if len(a) != len(b) {
		return nil
	}

	aIsVariadic := t.FuncArgs().Variadic != nil
	bIsVariadic := other.FuncArgs().Variadic != nil

	if aIsVariadic && !bIsVariadic {
		return nil
	} else if bIsVariadic && !aIsVariadic {
		return nil
	}

	args := make([]Type, len(a))
	for i := range a {
		args[i] = Or(a[i], b[i])
	}

	result := NewFunction(args, Or(t.Result(), other.Result()))
	result.variadic = Or(t.FuncArgs().Variadic, other.FuncArgs().Variadic)

	return result
}

// FuncArgs represents the arguments that can be passed to a function.
type FuncArgs struct {
	Args     []Type `json:"args,omitempty"`
	Variadic Type   `json:"variadic,omitempty"`
}

func (a FuncArgs) String() string {
	var buf []string
	for i := range a.Args {
		buf = append(buf, Sprint(a.Args[i]))
	}
	if a.Variadic != nil {
		buf = append(buf, Sprint(a.Variadic)+"...")
	}
	return "(" + strings.Join(buf, ", ") + ")"
}

func (a FuncArgs) Arg(x int) Type {
	if x < len(a.Args) {
		return a.Args[x]
	}
	return a.Variadic
}

// Compare returns -1, 0, 1 based on comparison between a and b.
func Compare(a, b Type) int {
	x := typeOrder(a)
	y := typeOrder(b)
	if x > y {
		return 1
	} else if x < y {
		return -1
	}
	switch a.(type) {
	case nil, Null, Boolean, Number, String:
		return 0
	case *Array:
		arrA := a.(*Array)
		arrB := b.(*Array)
		if arrA.dynamic != nil && arrB.dynamic == nil {
			return 1
		} else if arrB.dynamic != nil && arrA.dynamic == nil {
			return -1
		}
		if arrB.dynamic != nil && arrA.dynamic != nil {
			if cmp := Compare(arrA.dynamic, arrB.dynamic); cmp != 0 {
				return cmp
			}
		}
		return typeSliceCompare(arrA.static, arrB.static)
	case *Object:
		objA := a.(*Object)
		objB := b.(*Object)
		if objA.dynamic != nil && objB.dynamic == nil {
			return 1
		} else if objB.dynamic != nil && objA.dynamic == nil {
			return -1
		}
		if objA.dynamic != nil && objB.dynamic != nil {
			if cmp := Compare(objA.dynamic.Key, objB.dynamic.Key); cmp != 0 {
				return cmp
			}
			if cmp := Compare(objA.dynamic.Value, objB.dynamic.Value); cmp != 0 {
				return cmp
			}
		}

		lenStaticA := len(objA.static)
		lenStaticB := len(objB.static)

		minLen := lenStaticA
		if lenStaticB < minLen {
			minLen = lenStaticB
		}

		for i := 0; i < minLen; i++ {
			if cmp := util.Compare(objA.static[i].Key, objB.static[i].Key); cmp != 0 {
				return cmp
			}
			if cmp := Compare(objA.static[i].Value, objB.static[i].Value); cmp != 0 {
				return cmp
			}
		}

		if lenStaticA < lenStaticB {
			return -1
		} else if lenStaticB < lenStaticA {
			return 1
		}

		return 0
	case *Set:
		setA := a.(*Set)
		setB := b.(*Set)
		if setA.of == nil && setB.of == nil {
			return 0
		} else if setA.of == nil {
			return -1
		} else if setB.of == nil {
			return 1
		}
		return Compare(setA.of, setB.of)
	case Any:
		sl1 := typeSlice(a.(Any))
		sl2 := typeSlice(b.(Any))
		return typeSliceCompare(sl1, sl2)
	case *Function:
		fA := a.(*Function)
		fB := b.(*Function)
		if len(fA.args) < len(fB.args) {
			return -1
		} else if len(fA.args) > len(fB.args) {
			return 1
		}
		for i := 0; i < len(fA.args); i++ {
			if cmp := Compare(fA.args[i], fB.args[i]); cmp != 0 {
				return cmp
			}
		}
		if cmp := Compare(fA.result, fB.result); cmp != 0 {
			return cmp
		}
		return Compare(fA.variadic, fB.variadic)
	default:
		panic("unreachable")
	}
}

// Contains returns true if a is a superset or equal to b.
func Contains(a, b Type) bool {
	if any, ok := a.(Any); ok {
		return any.Contains(b)
	}
	return Compare(a, b) == 0
}

// Or returns a type that represents the union of a and b. If one type is a
// superset of the other, the superset is returned unchanged.
func Or(a, b Type) Type {
	if a == nil {
		return b
	} else if b == nil {
		return a
	}
	fA, ok1 := a.(*Function)
	fB, ok2 := b.(*Function)
	if ok1 && ok2 {
		return fA.Union(fB)
	} else if ok1 || ok2 {
		return nil
	}
	anyA, ok1 := a.(Any)
	anyB, ok2 := b.(Any)
	if ok1 {
		return anyA.Merge(b)
	}
	if ok2 {
		return anyB.Merge(a)
	}
	if Compare(a, b) == 0 {
		return a
	}
	return NewAny(a, b)
}

// Select returns a property or item of a.
func Select(a Type, x interface{}) Type {
	switch a := a.(type) {
	case *Array:
		n, ok := x.(json.Number)
		if !ok {
			return nil
		}
		pos, err := n.Int64()
		if err != nil {
			return nil
		}
		return a.Select(int(pos))
	case *Object:
		return a.Select(x)
	case *Set:
		tpe := TypeOf(x)
		if Compare(a.of, tpe) == 0 {
			return a.of
		}
		if any, ok := a.of.(Any); ok {
			if any.Contains(tpe) {
				return tpe
			}
		}
		return nil
	case Any:
		if Compare(a, A) == 0 {
			return A
		}
		var tpe Type
		for i := range a {
			// TODO(tsandall): test nil/nil
			tpe = Or(Select(a[i], x), tpe)
		}
		return tpe
	default:
		return nil
	}
}

// Keys returns the type of keys that can be enumerated for a. For arrays, the
// keys are always number types, for objects the keys are always string types,
// and for sets the keys are always the type of the set element.
func Keys(a Type) Type {
	switch a := a.(type) {
	case *Array:
		return N
	case *Object:
		var tpe Type
		for _, k := range a.Keys() {
			tpe = Or(tpe, TypeOf(k))
		}
		if a.dynamic != nil {
			tpe = Or(tpe, a.dynamic.Key)
		}
		return tpe
	case *Set:
		return a.of
	case Any:
		// TODO(tsandall): ditto test
		if Compare(a, A) == 0 {
			return A
		}
		var tpe Type
		for i := range a {
			tpe = Or(Keys(a[i]), tpe)
		}
		return tpe
	}
	return nil
}

// Values returns the type of values that can be enumerated for a.
func Values(a Type) Type {
	switch a := a.(type) {
	case *Array:
		var tpe Type
		for i := range a.static {
			tpe = Or(tpe, a.static[i])
		}
		return Or(tpe, a.dynamic)
	case *Object:
		var tpe Type
		for _, v := range a.static {
			tpe = Or(tpe, v.Value)
		}
		if a.dynamic != nil {
			tpe = Or(tpe, a.dynamic.Value)
		}
		return tpe
	case *Set:
		return a.of
	case Any:
		if Compare(a, A) == 0 {
			return A
		}
		var tpe Type
		for i := range a {
			tpe = Or(Values(a[i]), tpe)
		}
		return tpe
	}
	return nil
}

// Nil returns true if a's type is unknown.
func Nil(a Type) bool {
	switch a := a.(type) {
	case nil:
		return true
	case *Function:
		for i := range a.args {
			if Nil(a.args[i]) {
				return true
			}
		}
		return Nil(a.result)
	case *Array:
		for i := range a.static {
			if Nil(a.static[i]) {
				return true
			}
		}
		if a.dynamic != nil {
			return Nil(a.dynamic)
		}
	case *Object:
		for i := range a.static {
			if Nil(a.static[i].Value) {
				return true
			}
		}
		if a.dynamic != nil {
			return Nil(a.dynamic.Key) || Nil(a.dynamic.Value)
		}
	case *Set:
		return Nil(a.of)
	}
	return false
}

// TypeOf returns the type of the Golang native value.
func TypeOf(x interface{}) Type {
	switch x := x.(type) {
	case nil:
		return NewNull()
	case bool:
		return B
	case string:
		return S
	case json.Number:
		return N
	case map[string]interface{}:
		// The ast.ValueToInterface() function returns ast.Object values as map[string]interface{}
		// so map[string]interface{} must be handled here because the type checker uses the value
		// to interface conversion when inferring object types.
		static := make([]*StaticProperty, 0, len(x))
		for k, v := range x {
			static = append(static, NewStaticProperty(k, TypeOf(v)))
		}
		return NewObject(static, nil)
	case map[interface{}]interface{}:
		static := make([]*StaticProperty, 0, len(x))
		for k, v := range x {
			static = append(static, NewStaticProperty(k, TypeOf(v)))
		}
		return NewObject(static, nil)
	case []interface{}:
		static := make([]Type, len(x))
		for i := range x {
			static[i] = TypeOf(x[i])
		}
		return NewArray(static, nil)
	}
	panic("unreachable")
}

type typeSlice []Type

func (s typeSlice) Less(i, j int) bool { return Compare(s[i], s[j]) < 0 }
func (s typeSlice) Swap(i, j int)      { x := s[i]; s[i] = s[j]; s[j] = x }
func (s typeSlice) Len() int           { return len(s) }

func typeSliceCompare(a, b []Type) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if cmp := Compare(a[i], b[i]); cmp != 0 {
			return cmp
		}
	}
	if len(a) < len(b) {
		return -1
	} else if len(b) < len(a) {
		return 1
	}
	return 0
}

func typeOrder(x Type) int {
	switch x.(type) {
	case Null:
		return 0
	case Boolean:
		return 1
	case Number:
		return 2
	case String:
		return 3
	case *Array:
		return 4
	case *Object:
		return 5
	case *Set:
		return 6
	case Any:
		return 7
	case *Function:
		return 8
	case nil:
		return -1
	}
	panic("unreachable")
}
