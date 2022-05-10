// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// nolint: deadcode // Public API.
package ast

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/OneOfOne/xxhash"
	"github.com/pkg/errors"

	"github.com/open-policy-agent/opa/ast/location"
	"github.com/open-policy-agent/opa/util"
)

var errFindNotFound = fmt.Errorf("find: not found")

// Location records a position in source code.
type Location = location.Location

// NewLocation returns a new Location object.
func NewLocation(text []byte, file string, row int, col int) *Location {
	return location.NewLocation(text, file, row, col)
}

// Value declares the common interface for all Term values. Every kind of Term value
// in the language is represented as a type that implements this interface:
//
// - Null, Boolean, Number, String
// - Object, Array, Set
// - Variables, References
// - Array, Set, and Object Comprehensions
// - Calls
type Value interface {
	Compare(other Value) int      // Compare returns <0, 0, or >0 if this Value is less than, equal to, or greater than other, respectively.
	Find(path Ref) (Value, error) // Find returns value referred to by path or an error if path is not found.
	Hash() int                    // Returns hash code of the value.
	IsGround() bool               // IsGround returns true if this value is not a variable or contains no variables.
	String() string               // String returns a human readable string representation of the value.
}

// InterfaceToValue converts a native Go value x to a Value.
func InterfaceToValue(x interface{}) (Value, error) {
	switch x := x.(type) {
	case nil:
		return Null{}, nil
	case bool:
		return Boolean(x), nil
	case json.Number:
		return Number(x), nil
	case int64:
		return int64Number(x), nil
	case uint64:
		return uint64Number(x), nil
	case float64:
		return floatNumber(x), nil
	case int:
		return intNumber(x), nil
	case string:
		return String(x), nil
	case []interface{}:
		r := make([]*Term, len(x))
		for i, e := range x {
			e, err := InterfaceToValue(e)
			if err != nil {
				return nil, err
			}
			r[i] = &Term{Value: e}
		}
		return NewArray(r...), nil
	case map[string]interface{}:
		r := newobject(len(x))
		for k, v := range x {
			k, err := InterfaceToValue(k)
			if err != nil {
				return nil, err
			}
			v, err := InterfaceToValue(v)
			if err != nil {
				return nil, err
			}
			r.Insert(NewTerm(k), NewTerm(v))
		}
		return r, nil
	case map[string]string:
		r := newobject(len(x))
		for k, v := range x {
			k, err := InterfaceToValue(k)
			if err != nil {
				return nil, err
			}
			v, err := InterfaceToValue(v)
			if err != nil {
				return nil, err
			}
			r.Insert(NewTerm(k), NewTerm(v))
		}
		return r, nil
	default:
		ptr := util.Reference(x)
		if err := util.RoundTrip(ptr); err != nil {
			return nil, fmt.Errorf("ast: interface conversion: %w", err)
		}
		return InterfaceToValue(*ptr)
	}
}

// ValueFromReader returns an AST value from a JSON serialized value in the reader.
func ValueFromReader(r io.Reader) (Value, error) {
	var x interface{}
	if err := util.NewJSONDecoder(r).Decode(&x); err != nil {
		return nil, err
	}
	return InterfaceToValue(x)
}

// As converts v into a Go native type referred to by x.
func As(v Value, x interface{}) error {
	return util.NewJSONDecoder(bytes.NewBufferString(v.String())).Decode(x)
}

// Resolver defines the interface for resolving references to native Go values.
type Resolver interface {
	Resolve(ref Ref) (interface{}, error)
}

// ValueResolver defines the interface for resolving references to AST values.
type ValueResolver interface {
	Resolve(ref Ref) (Value, error)
}

// UnknownValueErr indicates a ValueResolver was unable to resolve a reference
// because the reference refers to an unknown value.
type UnknownValueErr struct{}

func (UnknownValueErr) Error() string {
	return "unknown value"
}

// IsUnknownValueErr returns true if the err is an UnknownValueErr.
func IsUnknownValueErr(err error) bool {
	_, ok := err.(UnknownValueErr)
	return ok
}

type illegalResolver struct{}

func (illegalResolver) Resolve(ref Ref) (interface{}, error) {
	return nil, fmt.Errorf("illegal value: %v", ref)
}

// ValueToInterface returns the Go representation of an AST value.  The AST
// value should not contain any values that require evaluation (e.g., vars,
// comprehensions, etc.)
func ValueToInterface(v Value, resolver Resolver) (interface{}, error) {
	return valueToInterface(v, resolver, JSONOpt{})
}

func valueToInterface(v Value, resolver Resolver, opt JSONOpt) (interface{}, error) {
	switch v := v.(type) {
	case Null:
		return nil, nil
	case Boolean:
		return bool(v), nil
	case Number:
		return json.Number(v), nil
	case String:
		return string(v), nil
	case *Array:
		buf := []interface{}{}
		for i := 0; i < v.Len(); i++ {
			x1, err := valueToInterface(v.Elem(i).Value, resolver, opt)
			if err != nil {
				return nil, err
			}
			buf = append(buf, x1)
		}
		return buf, nil
	case *object:
		buf := make(map[string]interface{}, v.Len())
		err := v.Iter(func(k, v *Term) error {
			ki, err := valueToInterface(k.Value, resolver, opt)
			if err != nil {
				return err
			}
			var str string
			var ok bool
			if str, ok = ki.(string); !ok {
				var buf bytes.Buffer
				if err := json.NewEncoder(&buf).Encode(ki); err != nil {
					return err
				}
				str = strings.TrimSpace(buf.String())
			}
			vi, err := valueToInterface(v.Value, resolver, opt)
			if err != nil {
				return err
			}
			buf[str] = vi
			return nil
		})
		if err != nil {
			return nil, err
		}
		return buf, nil
	case Set:
		buf := []interface{}{}
		iter := func(x *Term) error {
			x1, err := valueToInterface(x.Value, resolver, opt)
			if err != nil {
				return err
			}
			buf = append(buf, x1)
			return nil
		}
		var err error
		if opt.SortSets {
			err = v.Sorted().Iter(iter)
		} else {
			err = v.Iter(iter)
		}
		if err != nil {
			return nil, err
		}
		return buf, nil
	case Ref:
		return resolver.Resolve(v)
	default:
		return nil, fmt.Errorf("%v requires evaluation", TypeName(v))
	}
}

// JSON returns the JSON representation of v. The value must not contain any
// refs or terms that require evaluation (e.g., vars, comprehensions, etc.)
func JSON(v Value) (interface{}, error) {
	return JSONWithOpt(v, JSONOpt{})
}

// JSONOpt defines parameters for AST to JSON conversion.
type JSONOpt struct {
	SortSets bool // sort sets before serializing (this makes conversion more expensive)
}

// JSONWithOpt returns the JSON representation of v. The value must not contain any
// refs or terms that require evaluation (e.g., vars, comprehensions, etc.)
func JSONWithOpt(v Value, opt JSONOpt) (interface{}, error) {
	return valueToInterface(v, illegalResolver{}, opt)
}

// MustJSON returns the JSON representation of v. The value must not contain any
// refs or terms that require evaluation (e.g., vars, comprehensions, etc.) If
// the conversion fails, this function will panic. This function is mostly for
// test purposes.
func MustJSON(v Value) interface{} {
	r, err := JSON(v)
	if err != nil {
		panic(err)
	}
	return r
}

// MustInterfaceToValue converts a native Go value x to a Value. If the
// conversion fails, this function will panic. This function is mostly for test
// purposes.
func MustInterfaceToValue(x interface{}) Value {
	v, err := InterfaceToValue(x)
	if err != nil {
		panic(err)
	}
	return v
}

// Term is an argument to a function.
type Term struct {
	Value    Value     `json:"value"` // the value of the Term as represented in Go
	Location *Location `json:"-"`     // the location of the Term in the source
}

// NewTerm returns a new Term object.
func NewTerm(v Value) *Term {
	return &Term{
		Value: v,
	}
}

// SetLocation updates the term's Location and returns the term itself.
func (term *Term) SetLocation(loc *Location) *Term {
	term.Location = loc
	return term
}

// Loc returns the Location of term.
func (term *Term) Loc() *Location {
	if term == nil {
		return nil
	}
	return term.Location
}

// SetLoc sets the location on term.
func (term *Term) SetLoc(loc *Location) {
	term.SetLocation(loc)
}

// Copy returns a deep copy of term.
func (term *Term) Copy() *Term {

	if term == nil {
		return nil
	}

	cpy := *term

	switch v := term.Value.(type) {
	case Null, Boolean, Number, String, Var:
		cpy.Value = v
	case Ref:
		cpy.Value = v.Copy()
	case *Array:
		cpy.Value = v.Copy()
	case Set:
		cpy.Value = v.Copy()
	case *object:
		cpy.Value = v.Copy()
	case *ArrayComprehension:
		cpy.Value = v.Copy()
	case *ObjectComprehension:
		cpy.Value = v.Copy()
	case *SetComprehension:
		cpy.Value = v.Copy()
	case Call:
		cpy.Value = v.Copy()
	}

	return &cpy
}

// Equal returns true if this term equals the other term. Equality is
// defined for each kind of term.
func (term *Term) Equal(other *Term) bool {
	if term == nil && other != nil {
		return false
	}
	if term != nil && other == nil {
		return false
	}
	if term == other {
		return true
	}

	// TODO(tsandall): This early-exit avoids allocations for types that have
	// Equal() functions that just use == underneath. We should revisit the
	// other types and implement Equal() functions that do not require
	// allocations.
	switch v := term.Value.(type) {
	case Null:
		return v.Equal(other.Value)
	case Boolean:
		return v.Equal(other.Value)
	case Number:
		return v.Equal(other.Value)
	case String:
		return v.Equal(other.Value)
	case Var:
		return v.Equal(other.Value)
	}

	return term.Value.Compare(other.Value) == 0
}

// Get returns a value referred to by name from the term.
func (term *Term) Get(name *Term) *Term {
	switch v := term.Value.(type) {
	case *Array:
		return v.Get(name)
	case *object:
		return v.Get(name)
	case Set:
		if v.Contains(name) {
			return name
		}
	}
	return nil
}

// Hash returns the hash code of the Term's Value. Its Location
// is ignored.
func (term *Term) Hash() int {
	return term.Value.Hash()
}

// IsGround returns true if this term's Value is ground.
func (term *Term) IsGround() bool {
	return term.Value.IsGround()
}

// MarshalJSON returns the JSON encoding of the term.
//
// Specialized marshalling logic is required to include a type hint for Value.
func (term *Term) MarshalJSON() ([]byte, error) {
	d := map[string]interface{}{
		"type":  TypeName(term.Value),
		"value": term.Value,
	}
	return json.Marshal(d)
}

func (term *Term) String() string {
	return term.Value.String()
}

// UnmarshalJSON parses the byte array and stores the result in term.
// Specialized unmarshalling is required to handle Value.
func (term *Term) UnmarshalJSON(bs []byte) error {
	v := map[string]interface{}{}
	if err := util.UnmarshalJSON(bs, &v); err != nil {
		return err
	}
	val, err := unmarshalValue(v)
	if err != nil {
		return err
	}
	term.Value = val
	return nil
}

// Vars returns a VarSet with variables contained in this term.
func (term *Term) Vars() VarSet {
	vis := &VarVisitor{vars: VarSet{}}
	vis.Walk(term)
	return vis.vars
}

// IsConstant returns true if the AST value is constant.
func IsConstant(v Value) bool {
	found := false
	vis := GenericVisitor{
		func(x interface{}) bool {
			switch x.(type) {
			case Var, Ref, *ArrayComprehension, *ObjectComprehension, *SetComprehension, Call:
				found = true
				return true
			}
			return false
		},
	}
	vis.Walk(v)
	return !found
}

// IsComprehension returns true if the supplied value is a comprehension.
func IsComprehension(x Value) bool {
	switch x.(type) {
	case *ArrayComprehension, *ObjectComprehension, *SetComprehension:
		return true
	}
	return false
}

// ContainsRefs returns true if the Value v contains refs.
func ContainsRefs(v interface{}) bool {
	found := false
	WalkRefs(v, func(Ref) bool {
		found = true
		return found
	})
	return found
}

// ContainsComprehensions returns true if the Value v contains comprehensions.
func ContainsComprehensions(v interface{}) bool {
	found := false
	WalkClosures(v, func(x interface{}) bool {
		switch x.(type) {
		case *ArrayComprehension, *ObjectComprehension, *SetComprehension:
			found = true
			return found
		}
		return found
	})
	return found
}

// ContainsClosures returns true if the Value v contains closures.
func ContainsClosures(v interface{}) bool {
	found := false
	WalkClosures(v, func(x interface{}) bool {
		switch x.(type) {
		case *ArrayComprehension, *ObjectComprehension, *SetComprehension, *Every:
			found = true
			return found
		}
		return found
	})
	return found
}

// IsScalar returns true if the AST value is a scalar.
func IsScalar(v Value) bool {
	switch v.(type) {
	case String:
		return true
	case Number:
		return true
	case Boolean:
		return true
	case Null:
		return true
	}
	return false
}

// Null represents the null value defined by JSON.
type Null struct{}

// NullTerm creates a new Term with a Null value.
func NullTerm() *Term {
	return &Term{Value: Null{}}
}

// Equal returns true if the other term Value is also Null.
func (null Null) Equal(other Value) bool {
	switch other.(type) {
	case Null:
		return true
	default:
		return false
	}
}

// Compare compares null to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (null Null) Compare(other Value) int {
	return Compare(null, other)
}

// Find returns the current value or a not found error.
func (null Null) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return null, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code for the Value.
func (null Null) Hash() int {
	return 0
}

// IsGround always returns true.
func (Null) IsGround() bool {
	return true
}

func (null Null) String() string {
	return "null"
}

// Boolean represents a boolean value defined by JSON.
type Boolean bool

// BooleanTerm creates a new Term with a Boolean value.
func BooleanTerm(b bool) *Term {
	return &Term{Value: Boolean(b)}
}

// Equal returns true if the other Value is a Boolean and is equal.
func (bol Boolean) Equal(other Value) bool {
	switch other := other.(type) {
	case Boolean:
		return bol == other
	default:
		return false
	}
}

// Compare compares bol to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (bol Boolean) Compare(other Value) int {
	return Compare(bol, other)
}

// Find returns the current value or a not found error.
func (bol Boolean) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return bol, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code for the Value.
func (bol Boolean) Hash() int {
	if bol {
		return 1
	}
	return 0
}

// IsGround always returns true.
func (Boolean) IsGround() bool {
	return true
}

func (bol Boolean) String() string {
	return strconv.FormatBool(bool(bol))
}

// Number represents a numeric value as defined by JSON.
type Number json.Number

// NumberTerm creates a new Term with a Number value.
func NumberTerm(n json.Number) *Term {
	return &Term{Value: Number(n)}
}

// IntNumberTerm creates a new Term with an integer Number value.
func IntNumberTerm(i int) *Term {
	return &Term{Value: Number(strconv.Itoa(i))}
}

// UIntNumberTerm creates a new Term with an unsigned integer Number value.
func UIntNumberTerm(u uint64) *Term {
	return &Term{Value: uint64Number(u)}
}

// FloatNumberTerm creates a new Term with a floating point Number value.
func FloatNumberTerm(f float64) *Term {
	s := strconv.FormatFloat(f, 'g', -1, 64)
	return &Term{Value: Number(s)}
}

// Equal returns true if the other Value is a Number and is equal.
func (num Number) Equal(other Value) bool {
	switch other := other.(type) {
	case Number:
		return Compare(num, other) == 0
	default:
		return false
	}
}

// Compare compares num to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (num Number) Compare(other Value) int {
	return Compare(num, other)
}

// Find returns the current value or a not found error.
func (num Number) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return num, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code for the Value.
func (num Number) Hash() int {
	f, err := json.Number(num).Float64()
	if err != nil {
		bs := []byte(num)
		h := xxhash.Checksum64(bs)
		return int(h)
	}
	return int(f)
}

// Int returns the int representation of num if possible.
func (num Number) Int() (int, bool) {
	i64, ok := num.Int64()
	return int(i64), ok
}

// Int64 returns the int64 representation of num if possible.
func (num Number) Int64() (int64, bool) {
	i, err := json.Number(num).Int64()
	if err != nil {
		return 0, false
	}
	return i, true
}

// Float64 returns the float64 representation of num if possible.
func (num Number) Float64() (float64, bool) {
	f, err := json.Number(num).Float64()
	if err != nil {
		return 0, false
	}
	return f, true
}

// IsGround always returns true.
func (Number) IsGround() bool {
	return true
}

// MarshalJSON returns JSON encoded bytes representing num.
func (num Number) MarshalJSON() ([]byte, error) {
	return json.Marshal(json.Number(num))
}

func (num Number) String() string {
	return string(num)
}

func intNumber(i int) Number {
	return Number(strconv.Itoa(i))
}

func int64Number(i int64) Number {
	return Number(strconv.FormatInt(i, 10))
}

func uint64Number(u uint64) Number {
	return Number(strconv.FormatUint(u, 10))
}

func floatNumber(f float64) Number {
	return Number(strconv.FormatFloat(f, 'g', -1, 64))
}

// String represents a string value as defined by JSON.
type String string

// StringTerm creates a new Term with a String value.
func StringTerm(s string) *Term {
	return &Term{Value: String(s)}
}

// Equal returns true if the other Value is a String and is equal.
func (str String) Equal(other Value) bool {
	switch other := other.(type) {
	case String:
		return str == other
	default:
		return false
	}
}

// Compare compares str to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (str String) Compare(other Value) int {
	return Compare(str, other)
}

// Find returns the current value or a not found error.
func (str String) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return str, nil
	}
	return nil, errFindNotFound
}

// IsGround always returns true.
func (String) IsGround() bool {
	return true
}

func (str String) String() string {
	return strconv.Quote(string(str))
}

// Hash returns the hash code for the Value.
func (str String) Hash() int {
	h := xxhash.ChecksumString64S(string(str), hashSeed0)
	return int(h)
}

// Var represents a variable as defined by the language.
type Var string

// VarTerm creates a new Term with a Variable value.
func VarTerm(v string) *Term {
	return &Term{Value: Var(v)}
}

// Equal returns true if the other Value is a Variable and has the same value
// (name).
func (v Var) Equal(other Value) bool {
	switch other := other.(type) {
	case Var:
		return v == other
	default:
		return false
	}
}

// Compare compares v to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (v Var) Compare(other Value) int {
	return Compare(v, other)
}

// Find returns the current value or a not found error.
func (v Var) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return v, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code for the Value.
func (v Var) Hash() int {
	h := xxhash.ChecksumString64S(string(v), hashSeed0)
	return int(h)
}

// IsGround always returns false.
func (Var) IsGround() bool {
	return false
}

// IsWildcard returns true if this is a wildcard variable.
func (v Var) IsWildcard() bool {
	return strings.HasPrefix(string(v), WildcardPrefix)
}

// IsGenerated returns true if this variable was generated during compilation.
func (v Var) IsGenerated() bool {
	return strings.HasPrefix(string(v), "__local")
}

func (v Var) String() string {
	// Special case for wildcard so that string representation is parseable. The
	// parser mangles wildcard variables to make their names unique and uses an
	// illegal variable name character (WildcardPrefix) to avoid conflicts. When
	// we serialize the variable here, we need to make sure it's parseable.
	if v.IsWildcard() {
		return Wildcard.String()
	}
	return string(v)
}

// Ref represents a reference as defined by the language.
type Ref []*Term

// EmptyRef returns a new, empty reference.
func EmptyRef() Ref {
	return Ref([]*Term{})
}

// PtrRef returns a new reference against the head for the pointer
// s. Path components in the pointer are unescaped.
func PtrRef(head *Term, s string) (Ref, error) {
	s = strings.Trim(s, "/")
	if s == "" {
		return Ref{head}, nil
	}
	parts := strings.Split(s, "/")
	if max := math.MaxInt32; len(parts) >= max {
		return nil, fmt.Errorf("path too long: %s, %d > %d (max)", s, len(parts), max)
	}
	ref := make(Ref, uint(len(parts))+1)
	ref[0] = head
	for i := 0; i < len(parts); i++ {
		var err error
		parts[i], err = url.PathUnescape(parts[i])
		if err != nil {
			return nil, err
		}
		ref[i+1] = StringTerm(parts[i])
	}
	return ref, nil
}

// RefTerm creates a new Term with a Ref value.
func RefTerm(r ...*Term) *Term {
	return &Term{Value: Ref(r)}
}

// Append returns a copy of ref with the term appended to the end.
func (ref Ref) Append(term *Term) Ref {
	n := len(ref)
	dst := make(Ref, n+1)
	copy(dst, ref)
	dst[n] = term
	return dst
}

// Insert returns a copy of the ref with x inserted at pos. If pos < len(ref),
// existing elements are shifted to the right. If pos > len(ref)+1 this
// function panics.
func (ref Ref) Insert(x *Term, pos int) Ref {
	if pos == len(ref) {
		return ref.Append(x)
	} else if pos > len(ref)+1 {
		panic("illegal index")
	}
	cpy := make(Ref, len(ref)+1)
	for i := 0; i < pos; i++ {
		cpy[i] = ref[i]
	}
	cpy[pos] = x
	for i := pos; i < len(ref); i++ {
		cpy[i+1] = ref[i]
	}
	return cpy
}

// Extend returns a copy of ref with the terms from other appended. The head of
// other will be converted to a string.
func (ref Ref) Extend(other Ref) Ref {
	dst := make(Ref, len(ref)+len(other))
	copy(dst, ref)

	head := other[0].Copy()
	head.Value = String(head.Value.(Var))
	offset := len(ref)
	dst[offset] = head
	for i := range other[1:] {
		dst[offset+i+1] = other[i+1]
	}
	return dst
}

// Concat returns a ref with the terms appended.
func (ref Ref) Concat(terms []*Term) Ref {
	if len(terms) == 0 {
		return ref
	}
	cpy := make(Ref, len(ref)+len(terms))
	copy(cpy, ref)

	for i := range terms {
		cpy[len(ref)+i] = terms[i]
	}
	return cpy
}

// Dynamic returns the offset of the first non-constant operand of ref.
func (ref Ref) Dynamic() int {
	switch ref[0].Value.(type) {
	case Call:
		return 0
	}
	for i := 1; i < len(ref); i++ {
		if !IsConstant(ref[i].Value) {
			return i
		}
	}
	return -1
}

// Copy returns a deep copy of ref.
func (ref Ref) Copy() Ref {
	return termSliceCopy(ref)
}

// Equal returns true if ref is equal to other.
func (ref Ref) Equal(other Value) bool {
	return Compare(ref, other) == 0
}

// Compare compares ref to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (ref Ref) Compare(other Value) int {
	return Compare(ref, other)
}

// Find returns the current value or a "not found" error.
func (ref Ref) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return ref, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code for the Value.
func (ref Ref) Hash() int {
	return termSliceHash(ref)
}

// HasPrefix returns true if the other ref is a prefix of this ref.
func (ref Ref) HasPrefix(other Ref) bool {
	if len(other) > len(ref) {
		return false
	}
	for i := range other {
		if !ref[i].Equal(other[i]) {
			return false
		}
	}
	return true
}

// ConstantPrefix returns the constant portion of the ref starting from the head.
func (ref Ref) ConstantPrefix() Ref {
	ref = ref.Copy()

	i := ref.Dynamic()
	if i < 0 {
		return ref
	}
	return ref[:i]
}

// GroundPrefix returns the ground portion of the ref starting from the head. By
// definition, the head of the reference is always ground.
func (ref Ref) GroundPrefix() Ref {
	prefix := make(Ref, 0, len(ref))

	for i, x := range ref {
		if i > 0 && !x.IsGround() {
			break
		}
		prefix = append(prefix, x)
	}

	return prefix
}

// IsGround returns true if all of the parts of the Ref are ground.
func (ref Ref) IsGround() bool {
	if len(ref) == 0 {
		return true
	}
	return termSliceIsGround(ref[1:])
}

// IsNested returns true if this ref contains other Refs.
func (ref Ref) IsNested() bool {
	for _, x := range ref {
		if _, ok := x.Value.(Ref); ok {
			return true
		}
	}
	return false
}

// Ptr returns a slash-separated path string for this ref. If the ref
// contains non-string terms this function returns an error. Path
// components are escaped.
func (ref Ref) Ptr() (string, error) {
	parts := make([]string, 0, len(ref)-1)
	for _, term := range ref[1:] {
		if str, ok := term.Value.(String); ok {
			parts = append(parts, url.PathEscape(string(str)))
		} else {
			return "", fmt.Errorf("invalid path value type")
		}
	}
	return strings.Join(parts, "/"), nil
}

var varRegexp = regexp.MustCompile("^[[:alpha:]_][[:alpha:][:digit:]_]*$")

func (ref Ref) String() string {
	if len(ref) == 0 {
		return ""
	}
	buf := []string{ref[0].Value.String()}
	path := ref[1:]
	for _, p := range path {
		switch p := p.Value.(type) {
		case String:
			str := string(p)
			if varRegexp.MatchString(str) && len(buf) > 0 && !IsKeyword(str) {
				buf = append(buf, "."+str)
			} else {
				buf = append(buf, "["+p.String()+"]")
			}
		default:
			buf = append(buf, "["+p.String()+"]")
		}
	}
	return strings.Join(buf, "")
}

// OutputVars returns a VarSet containing variables that would be bound by evaluating
//  this expression in isolation.
func (ref Ref) OutputVars() VarSet {
	vis := NewVarVisitor().WithParams(VarVisitorParams{SkipRefHead: true})
	vis.Walk(ref)
	return vis.Vars()
}

// QueryIterator defines the interface for querying AST documents with references.
type QueryIterator func(map[Var]Value, Value) error

// ArrayTerm creates a new Term with an Array value.
func ArrayTerm(a ...*Term) *Term {
	return &Term{Value: &Array{elems: a, hash: 0, ground: termSliceIsGround(a)}}
}

// NewArray creates an Array with the terms provided. The array will
// use the provided term slice.
func NewArray(a ...*Term) *Array {
	return &Array{elems: a, hash: 0, ground: termSliceIsGround(a)}
}

// Array represents an array as defined by the language. Arrays are similar to the
// same types as defined by JSON with the exception that they can contain Vars
// and References.
type Array struct {
	elems  []*Term
	hash   int
	ground bool
}

// Copy returns a deep copy of arr.
func (arr *Array) Copy() *Array {
	return &Array{
		elems:  termSliceCopy(arr.elems),
		hash:   arr.hash,
		ground: arr.IsGround()}
}

// Equal returns true if arr is equal to other.
func (arr *Array) Equal(other Value) bool {
	return Compare(arr, other) == 0
}

// Compare compares arr to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (arr *Array) Compare(other Value) int {
	return Compare(arr, other)
}

// Find returns the value at the index or an out-of-range error.
func (arr *Array) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return arr, nil
	}
	num, ok := path[0].Value.(Number)
	if !ok {
		return nil, errFindNotFound
	}
	i, ok := num.Int()
	if !ok {
		return nil, errFindNotFound
	}
	if i < 0 || i >= arr.Len() {
		return nil, errFindNotFound
	}
	return arr.Elem(i).Value.Find(path[1:])
}

// Get returns the element at pos or nil if not possible.
func (arr *Array) Get(pos *Term) *Term {
	num, ok := pos.Value.(Number)
	if !ok {
		return nil
	}

	i, ok := num.Int()
	if !ok {
		return nil
	}

	if i >= 0 && i < len(arr.elems) {
		return arr.elems[i]
	}

	return nil
}

// Sorted returns a new Array that contains the sorted elements of arr.
func (arr *Array) Sorted() *Array {
	cpy := make([]*Term, len(arr.elems))
	for i := range cpy {
		cpy[i] = arr.elems[i]
	}
	sort.Sort(termSlice(cpy))
	a := NewArray(cpy...)
	a.hash = arr.hash
	return a
}

// Hash returns the hash code for the Value.
func (arr *Array) Hash() int {
	if arr.hash == 0 {
		arr.hash = termSliceHash(arr.elems)
	}

	return arr.hash
}

// IsGround returns true if all of the Array elements are ground.
func (arr *Array) IsGround() bool {
	return arr.ground
}

// MarshalJSON returns JSON encoded bytes representing arr.
func (arr *Array) MarshalJSON() ([]byte, error) {
	if len(arr.elems) == 0 {
		return []byte(`[]`), nil
	}
	return json.Marshal(arr.elems)
}

func (arr *Array) String() string {
	var b strings.Builder
	b.WriteRune('[')
	for i, e := range arr.elems {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(e.String())
	}
	b.WriteRune(']')
	return b.String()
}

// Len returns the number of elements in the array.
func (arr *Array) Len() int {
	return len(arr.elems)
}

// Elem returns the element i of arr.
func (arr *Array) Elem(i int) *Term {
	return arr.elems[i]
}

// set sets the element i of arr.
func (arr *Array) set(i int, v *Term) {
	arr.ground = arr.ground && v.IsGround()
	arr.elems[i] = v
	arr.hash = 0
}

// Slice returns a slice of arr starting from i index to j. -1
// indicates the end of the array. The returned value array is not a
// copy and any modifications to either of arrays may be reflected to
// the other.
func (arr *Array) Slice(i, j int) *Array {
	var elems []*Term
	if j == -1 {
		elems = arr.elems[i:]
	} else {
		elems = arr.elems[i:j]
	}
	// If arr is ground, the slice is, too.
	// If it's not, the slice could still be.
	gr := arr.ground || termSliceIsGround(elems)
	return &Array{elems: elems, ground: gr}
}

// Iter calls f on each element in arr. If f returns an error,
// iteration stops and the return value is the error.
func (arr *Array) Iter(f func(*Term) error) error {
	for i := range arr.elems {
		if err := f(arr.elems[i]); err != nil {
			return err
		}
	}
	return nil
}

// Until calls f on each element in arr. If f returns true, iteration stops.
func (arr *Array) Until(f func(*Term) bool) bool {
	err := arr.Iter(func(t *Term) error {
		if f(t) {
			return errStop
		}
		return nil
	})
	return err != nil
}

// Foreach calls f on each element in arr.
func (arr *Array) Foreach(f func(*Term)) {
	_ = arr.Iter(func(t *Term) error {
		f(t)
		return nil
	}) // ignore error
}

// Append appends a term to arr, returning the appended array.
func (arr *Array) Append(v *Term) *Array {
	cpy := *arr
	cpy.elems = append(arr.elems, v)
	cpy.hash = 0
	cpy.ground = arr.ground && v.IsGround()
	return &cpy
}

// Set represents a set as defined by the language.
type Set interface {
	Value
	Len() int
	Copy() Set
	Diff(Set) Set
	Intersect(Set) Set
	Union(Set) Set
	Add(*Term)
	Iter(func(*Term) error) error
	Until(func(*Term) bool) bool
	Foreach(func(*Term))
	Contains(*Term) bool
	Map(func(*Term) (*Term, error)) (Set, error)
	Reduce(*Term, func(*Term, *Term) (*Term, error)) (*Term, error)
	Sorted() *Array
	Slice() []*Term
}

// NewSet returns a new Set containing t.
func NewSet(t ...*Term) Set {
	s := newset(len(t))
	for i := range t {
		s.Add(t[i])
	}
	return s
}

func newset(n int) *set {
	var keys []*Term
	if n > 0 {
		keys = make([]*Term, 0, n)
	}
	return &set{
		elems:  make(map[int]*Term, n),
		keys:   keys,
		hash:   0,
		ground: true,
	}
}

// SetTerm returns a new Term representing a set containing terms t.
func SetTerm(t ...*Term) *Term {
	set := NewSet(t...)
	return &Term{
		Value: set,
	}
}

type set struct {
	elems  map[int]*Term
	keys   []*Term
	hash   int
	ground bool
}

// Copy returns a deep copy of s.
func (s *set) Copy() Set {
	cpy := newset(s.Len())
	s.Foreach(func(x *Term) {
		cpy.Add(x.Copy())
	})
	cpy.hash = s.hash
	cpy.ground = s.ground
	return cpy
}

// IsGround returns true if all terms in s are ground.
func (s *set) IsGround() bool {
	return s.ground
}

// Hash returns a hash code for s.
func (s *set) Hash() int {
	if s.hash == 0 {
		s.Foreach(func(x *Term) {
			s.hash += x.Hash()
		})
	}
	return s.hash
}

func (s *set) String() string {
	if s.Len() == 0 {
		return "set()"
	}
	var b strings.Builder
	b.WriteRune('{')
	for i := range s.keys {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(s.keys[i].Value.String())
	}
	b.WriteRune('}')
	return b.String()
}

// Compare compares s to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (s *set) Compare(other Value) int {
	o1 := sortOrder(s)
	o2 := sortOrder(other)
	if o1 < o2 {
		return -1
	} else if o1 > o2 {
		return 1
	}
	t := other.(*set)
	return termSliceCompare(s.keys, t.keys)
}

// Find returns the set or dereferences the element itself.
func (s *set) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return s, nil
	}
	if !s.Contains(path[0]) {
		return nil, errFindNotFound
	}
	return path[0].Value.Find(path[1:])
}

// Diff returns elements in s that are not in other.
func (s *set) Diff(other Set) Set {
	r := NewSet()
	s.Foreach(func(x *Term) {
		if !other.Contains(x) {
			r.Add(x)
		}
	})
	return r
}

// Intersect returns the set containing elements in both s and other.
func (s *set) Intersect(other Set) Set {
	o := other.(*set)
	n, m := s.Len(), o.Len()
	ss := s
	so := o
	if m < n {
		ss = o
		so = s
		n = m
	}

	r := newset(n)
	ss.Foreach(func(x *Term) {
		if so.Contains(x) {
			r.Add(x)
		}
	})
	return r
}

// Union returns the set containing all elements of s and other.
func (s *set) Union(other Set) Set {
	r := NewSet()
	s.Foreach(func(x *Term) {
		r.Add(x)
	})
	other.Foreach(func(x *Term) {
		r.Add(x)
	})
	return r
}

// Add updates s to include t.
func (s *set) Add(t *Term) {
	s.insert(t)
}

// Iter calls f on each element in s. If f returns an error, iteration stops
// and the return value is the error.
func (s *set) Iter(f func(*Term) error) error {
	for i := range s.keys {
		if err := f(s.keys[i]); err != nil {
			return err
		}
	}
	return nil
}

var errStop = errors.New("stop")

// Until calls f on each element in s. If f returns true, iteration stops.
func (s *set) Until(f func(*Term) bool) bool {
	err := s.Iter(func(t *Term) error {
		if f(t) {
			return errStop
		}
		return nil
	})
	return err != nil
}

// Foreach calls f on each element in s.
func (s *set) Foreach(f func(*Term)) {
	_ = s.Iter(func(t *Term) error {
		f(t)
		return nil
	}) // ignore error
}

// Map returns a new Set obtained by applying f to each value in s.
func (s *set) Map(f func(*Term) (*Term, error)) (Set, error) {
	set := NewSet()
	err := s.Iter(func(x *Term) error {
		term, err := f(x)
		if err != nil {
			return err
		}
		set.Add(term)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return set, nil
}

// Reduce returns a Term produced by applying f to each value in s. The first
// argument to f is the reduced value (starting with i) and the second argument
// to f is the element in s.
func (s *set) Reduce(i *Term, f func(*Term, *Term) (*Term, error)) (*Term, error) {
	err := s.Iter(func(x *Term) error {
		var err error
		i, err = f(i, x)
		if err != nil {
			return err
		}
		return nil
	})
	return i, err
}

// Contains returns true if t is in s.
func (s *set) Contains(t *Term) bool {
	return s.get(t) != nil
}

// Len returns the number of elements in the set.
func (s *set) Len() int {
	return len(s.keys)
}

// MarshalJSON returns JSON encoded bytes representing s.
func (s *set) MarshalJSON() ([]byte, error) {
	if s.keys == nil {
		return []byte(`[]`), nil
	}
	return json.Marshal(s.keys)
}

// Sorted returns an Array that contains the sorted elements of s.
func (s *set) Sorted() *Array {
	cpy := make([]*Term, len(s.keys))
	for i := range s.keys {
		cpy[i] = s.keys[i]
	}
	sort.Sort(termSlice(cpy))
	return NewArray(cpy...)
}

// Slice returns a slice of terms contained in the set.
func (s *set) Slice() []*Term {
	return s.keys
}

func (s *set) insert(x *Term) {
	hash := x.Hash()
	// This `equal` utility is duplicated and manually inlined a number of
	// time in this file.  Inlining it avoids heap allocations, so it makes
	// a big performance difference: some operations like lookup become twice
	// as slow without it.
	var equal func(v Value) bool

	switch x := x.Value.(type) {
	case Null, Boolean, String, Var:
		equal = func(y Value) bool { return x == y }
	case Number:
		if xi, err := json.Number(x).Int64(); err == nil {
			equal = func(y Value) bool {
				if y, ok := y.(Number); ok {
					if yi, err := json.Number(y).Int64(); err == nil {
						return xi == yi
					}
				}

				return false
			}
			break
		}

		// We use big.Rat for comparing big numbers.
		// It replaces big.Float due to following reason:
		// big.Float comes with a default precision of 64, and setting a
		// larger precision results in more memory being allocated
		// (regardless of the actual number we are parsing with SetString).
		//
		// Note: If we're so close to zero that big.Float says we are zero, do
		// *not* big.Rat).SetString on the original string it'll potentially
		// take very long.
		var a *big.Rat
		fa, ok := new(big.Float).SetString(string(x))
		if !ok {
			panic("illegal value")
		}
		if fa.IsInt() {
			if i, _ := fa.Int64(); i == 0 {
				a = new(big.Rat).SetInt64(0)
			}
		}
		if a == nil {
			a, ok = new(big.Rat).SetString(string(x))
			if !ok {
				panic("illegal value")
			}
		}

		equal = func(b Value) bool {
			if bNum, ok := b.(Number); ok {
				var b *big.Rat
				fb, ok := new(big.Float).SetString(string(bNum))
				if !ok {
					panic("illegal value")
				}
				if fb.IsInt() {
					if i, _ := fb.Int64(); i == 0 {
						b = new(big.Rat).SetInt64(0)
					}
				}
				if b == nil {
					b, ok = new(big.Rat).SetString(string(bNum))
					if !ok {
						panic("illegal value")
					}
				}

				return a.Cmp(b) == 0
			}

			return false
		}
	default:
		equal = func(y Value) bool { return Compare(x, y) == 0 }
	}

	for curr, ok := s.elems[hash]; ok; {
		if equal(curr.Value) {
			return
		}

		hash++
		curr, ok = s.elems[hash]
	}

	s.elems[hash] = x
	i := sort.Search(len(s.keys), func(i int) bool { return Compare(x, s.keys[i]) < 0 })
	if i < len(s.keys) {
		// insert at position `i`:
		s.keys = append(s.keys, nil)   // add some space
		copy(s.keys[i+1:], s.keys[i:]) // move things over
		s.keys[i] = x                  // drop it in position
	} else {
		s.keys = append(s.keys, x)
	}

	s.hash = 0
	s.ground = s.ground && x.IsGround()
}

func (s *set) get(x *Term) *Term {
	hash := x.Hash()
	// This `equal` utility is duplicated and manually inlined a number of
	// time in this file.  Inlining it avoids heap allocations, so it makes
	// a big performance difference: some operations like lookup become twice
	// as slow without it.
	var equal func(v Value) bool

	switch x := x.Value.(type) {
	case Null, Boolean, String, Var:
		equal = func(y Value) bool { return x == y }
	case Number:
		if xi, err := json.Number(x).Int64(); err == nil {
			equal = func(y Value) bool {
				if y, ok := y.(Number); ok {
					if yi, err := json.Number(y).Int64(); err == nil {
						return xi == yi
					}
				}

				return false
			}
			break
		}

		// We use big.Rat for comparing big numbers.
		// It replaces big.Float due to following reason:
		// big.Float comes with a default precision of 64, and setting a
		// larger precision results in more memory being allocated
		// (regardless of the actual number we are parsing with SetString).
		//
		// Note: If we're so close to zero that big.Float says we are zero, do
		// *not* big.Rat).SetString on the original string it'll potentially
		// take very long.
		var a *big.Rat
		fa, ok := new(big.Float).SetString(string(x))
		if !ok {
			panic("illegal value")
		}
		if fa.IsInt() {
			if i, _ := fa.Int64(); i == 0 {
				a = new(big.Rat).SetInt64(0)
			}
		}
		if a == nil {
			a, ok = new(big.Rat).SetString(string(x))
			if !ok {
				panic("illegal value")
			}
		}

		equal = func(b Value) bool {
			if bNum, ok := b.(Number); ok {
				var b *big.Rat
				fb, ok := new(big.Float).SetString(string(bNum))
				if !ok {
					panic("illegal value")
				}
				if fb.IsInt() {
					if i, _ := fb.Int64(); i == 0 {
						b = new(big.Rat).SetInt64(0)
					}
				}
				if b == nil {
					b, ok = new(big.Rat).SetString(string(bNum))
					if !ok {
						panic("illegal value")
					}
				}

				return a.Cmp(b) == 0
			}
			return false

		}

	default:
		equal = func(y Value) bool { return Compare(x, y) == 0 }
	}

	for curr, ok := s.elems[hash]; ok; {
		if equal(curr.Value) {
			return curr
		}

		hash++
		curr, ok = s.elems[hash]
	}
	return nil
}

// Object represents an object as defined by the language.
type Object interface {
	Value
	Len() int
	Get(*Term) *Term
	Copy() Object
	Insert(*Term, *Term)
	Iter(func(*Term, *Term) error) error
	Until(func(*Term, *Term) bool) bool
	Foreach(func(*Term, *Term))
	Map(func(*Term, *Term) (*Term, *Term, error)) (Object, error)
	Diff(other Object) Object
	Intersect(other Object) [][3]*Term
	Merge(other Object) (Object, bool)
	MergeWith(other Object, conflictResolver func(v1, v2 *Term) (*Term, bool)) (Object, bool)
	Filter(filter Object) (Object, error)
	Keys() []*Term
	Elem(i int) (*Term, *Term)
	get(k *Term) *objectElem // To prevent external implementations
}

// NewObject creates a new Object with t.
func NewObject(t ...[2]*Term) Object {
	obj := newobject(len(t))
	for i := range t {
		obj.Insert(t[i][0], t[i][1])
	}
	return obj
}

// ObjectTerm creates a new Term with an Object value.
func ObjectTerm(o ...[2]*Term) *Term {
	return &Term{Value: NewObject(o...)}
}

type object struct {
	elems  map[int]*objectElem
	keys   objectElemSlice
	ground int // number of key and value grounds. Counting is
	// required to support insert's key-value replace.
	hash int
}

func newobject(n int) *object {
	var keys objectElemSlice
	if n > 0 {
		keys = make(objectElemSlice, 0, n)
	}
	return &object{
		elems:  make(map[int]*objectElem, n),
		keys:   keys,
		ground: 0,
		hash:   0,
	}
}

type objectElem struct {
	key   *Term
	value *Term
	next  *objectElem
}

type objectElemSlice []*objectElem

func (s objectElemSlice) Less(i, j int) bool { return Compare(s[i].key.Value, s[j].key.Value) < 0 }
func (s objectElemSlice) Swap(i, j int)      { x := s[i]; s[i] = s[j]; s[j] = x }
func (s objectElemSlice) Len() int           { return len(s) }

// Item is a helper for constructing an tuple containing two Terms
// representing a key/value pair in an Object.
func Item(key, value *Term) [2]*Term {
	return [2]*Term{key, value}
}

// Compare compares obj to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (obj *object) Compare(other Value) int {
	o1 := sortOrder(obj)
	o2 := sortOrder(other)
	if o1 < o2 {
		return -1
	} else if o2 < o1 {
		return 1
	}
	a := obj
	b := other.(*object)
	minLen := len(a.keys)
	if len(b.keys) < len(a.keys) {
		minLen = len(b.keys)
	}
	for i := 0; i < minLen; i++ {
		keysCmp := Compare(a.keys[i].key, b.keys[i].key)
		if keysCmp < 0 {
			return -1
		}
		if keysCmp > 0 {
			return 1
		}
		valA := a.keys[i].value
		valB := b.keys[i].value
		valCmp := Compare(valA, valB)
		if valCmp != 0 {
			return valCmp
		}
	}
	if len(a.keys) < len(b.keys) {
		return -1
	}
	if len(b.keys) < len(a.keys) {
		return 1
	}
	return 0
}

// Find returns the value at the key or undefined.
func (obj *object) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return obj, nil
	}
	value := obj.Get(path[0])
	if value == nil {
		return nil, errFindNotFound
	}
	return value.Value.Find(path[1:])
}

func (obj *object) Insert(k, v *Term) {
	obj.insert(k, v)
}

// Get returns the value of k in obj if k exists, otherwise nil.
func (obj *object) Get(k *Term) *Term {
	if elem := obj.get(k); elem != nil {
		return elem.value
	}
	return nil
}

// Hash returns the hash code for the Value.
func (obj *object) Hash() int {
	if obj.hash == 0 {
		for h, curr := range obj.elems {
			for ; curr != nil; curr = curr.next {
				obj.hash += h
				obj.hash += curr.value.Hash()
			}
		}
	}
	return obj.hash
}

// IsGround returns true if all of the Object key/value pairs are ground.
func (obj *object) IsGround() bool {
	return obj.ground == 2*len(obj.keys)
}

// Copy returns a deep copy of obj.
func (obj *object) Copy() Object {
	cpy, _ := obj.Map(func(k, v *Term) (*Term, *Term, error) {
		return k.Copy(), v.Copy(), nil
	})
	cpy.(*object).hash = obj.hash
	return cpy
}

// Diff returns a new Object that contains only the key/value pairs that exist in obj.
func (obj *object) Diff(other Object) Object {
	r := NewObject()
	obj.Foreach(func(k, v *Term) {
		if other.Get(k) == nil {
			r.Insert(k, v)
		}
	})
	return r
}

// Intersect returns a slice of term triplets that represent the intersection of keys
// between obj and other. For each intersecting key, the values from obj and other are included
// as the last two terms in the triplet (respectively).
func (obj *object) Intersect(other Object) [][3]*Term {
	r := [][3]*Term{}
	obj.Foreach(func(k, v *Term) {
		if v2 := other.Get(k); v2 != nil {
			r = append(r, [3]*Term{k, v, v2})
		}
	})
	return r
}

// Iter calls the function f for each key-value pair in the object. If f
// returns an error, iteration stops and the error is returned.
func (obj *object) Iter(f func(*Term, *Term) error) error {
	for _, node := range obj.keys {
		if err := f(node.key, node.value); err != nil {
			return err
		}
	}
	return nil
}

// Until calls f for each key-value pair in the object. If f returns
// true, iteration stops and Until returns true. Otherwise, return
// false.
func (obj *object) Until(f func(*Term, *Term) bool) bool {
	err := obj.Iter(func(k, v *Term) error {
		if f(k, v) {
			return errStop
		}
		return nil
	})
	return err != nil
}

// Foreach calls f for each key-value pair in the object.
func (obj *object) Foreach(f func(*Term, *Term)) {
	_ = obj.Iter(func(k, v *Term) error {
		f(k, v)
		return nil
	}) // ignore error
}

// Map returns a new Object constructed by mapping each element in the object
// using the function f.
func (obj *object) Map(f func(*Term, *Term) (*Term, *Term, error)) (Object, error) {
	cpy := newobject(obj.Len())
	err := obj.Iter(func(k, v *Term) error {
		var err error
		k, v, err = f(k, v)
		if err != nil {
			return err
		}
		cpy.insert(k, v)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cpy, nil
}

// Keys returns the keys of obj.
func (obj *object) Keys() []*Term {
	keys := make([]*Term, len(obj.keys))

	for i, elem := range obj.keys {
		keys[i] = elem.key
	}

	return keys
}

func (obj *object) Elem(i int) (*Term, *Term) {
	return obj.keys[i].key, obj.keys[i].value
}

// MarshalJSON returns JSON encoded bytes representing obj.
func (obj *object) MarshalJSON() ([]byte, error) {
	sl := make([][2]*Term, obj.Len())
	for i, node := range obj.keys {
		sl[i] = Item(node.key, node.value)
	}
	return json.Marshal(sl)
}

// Merge returns a new Object containing the non-overlapping keys of obj and other. If there are
// overlapping keys between obj and other, the values of associated with the keys are merged. Only
// objects can be merged with other objects. If the values cannot be merged, the second turn value
// will be false.
func (obj object) Merge(other Object) (Object, bool) {
	return obj.MergeWith(other, func(v1, v2 *Term) (*Term, bool) {
		obj1, ok1 := v1.Value.(Object)
		obj2, ok2 := v2.Value.(Object)
		if !ok1 || !ok2 {
			return nil, true
		}
		obj3, ok := obj1.Merge(obj2)
		if !ok {
			return nil, true
		}
		return NewTerm(obj3), false
	})
}

// MergeWith returns a new Object containing the merged keys of obj and other.
// If there are overlapping keys between obj and other, the conflictResolver
// is called. The conflictResolver can return a merged value and a boolean
// indicating if the merge has failed and should stop.
func (obj object) MergeWith(other Object, conflictResolver func(v1, v2 *Term) (*Term, bool)) (Object, bool) {
	result := NewObject()
	stop := obj.Until(func(k, v *Term) bool {
		v2 := other.Get(k)
		// The key didn't exist in other, keep the original value
		if v2 == nil {
			result.Insert(k, v)
			return false
		}

		// The key exists in both, resolve the conflict if possible
		merged, stop := conflictResolver(v, v2)
		if !stop {
			result.Insert(k, merged)
		}
		return stop
	})

	if stop {
		return nil, false
	}

	// Copy in any values from other for keys that don't exist in obj
	other.Foreach(func(k, v *Term) {
		if v2 := obj.Get(k); v2 == nil {
			result.Insert(k, v)
		}
	})
	return result, true
}

// Filter returns a new object from values in obj where the keys are
// found in filter. Array indices for values can be specified as
// number strings.
func (obj *object) Filter(filter Object) (Object, error) {
	filtered, err := filterObject(obj, filter)
	if err != nil {
		return nil, err
	}
	return filtered.(Object), nil
}

// Len returns the number of elements in the object.
func (obj object) Len() int {
	return len(obj.keys)
}

func (obj object) String() string {
	var b strings.Builder
	b.WriteRune('{')

	for i, elem := range obj.keys {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(elem.key.String())
		b.WriteString(": ")
		b.WriteString(elem.value.String())
	}
	b.WriteRune('}')
	return b.String()
}

func (obj *object) get(k *Term) *objectElem {
	hash := k.Hash()

	// This `equal` utility is duplicated and manually inlined a number of
	// time in this file.  Inlining it avoids heap allocations, so it makes
	// a big performance difference: some operations like lookup become twice
	// as slow without it.
	var equal func(v Value) bool

	switch x := k.Value.(type) {
	case Null, Boolean, String, Var:
		equal = func(y Value) bool { return x == y }
	case Number:
		if xi, err := json.Number(x).Int64(); err == nil {
			equal = func(y Value) bool {
				if y, ok := y.(Number); ok {
					if yi, err := json.Number(y).Int64(); err == nil {
						return xi == yi
					}
				}

				return false
			}
			break
		}

		// We use big.Rat for comparing big numbers.
		// It replaces big.Float due to following reason:
		// big.Float comes with a default precision of 64, and setting a
		// larger precision results in more memory being allocated
		// (regardless of the actual number we are parsing with SetString).
		//
		// Note: If we're so close to zero that big.Float says we are zero, do
		// *not* big.Rat).SetString on the original string it'll potentially
		// take very long.
		var a *big.Rat
		fa, ok := new(big.Float).SetString(string(x))
		if !ok {
			panic("illegal value")
		}
		if fa.IsInt() {
			if i, _ := fa.Int64(); i == 0 {
				a = new(big.Rat).SetInt64(0)
			}
		}
		if a == nil {
			a, ok = new(big.Rat).SetString(string(x))
			if !ok {
				panic("illegal value")
			}
		}

		equal = func(b Value) bool {
			if bNum, ok := b.(Number); ok {
				var b *big.Rat
				fb, ok := new(big.Float).SetString(string(bNum))
				if !ok {
					panic("illegal value")
				}
				if fb.IsInt() {
					if i, _ := fb.Int64(); i == 0 {
						b = new(big.Rat).SetInt64(0)
					}
				}
				if b == nil {
					b, ok = new(big.Rat).SetString(string(bNum))
					if !ok {
						panic("illegal value")
					}
				}

				return a.Cmp(b) == 0
			}

			return false
		}
	default:
		equal = func(y Value) bool { return Compare(x, y) == 0 }
	}

	for curr := obj.elems[hash]; curr != nil; curr = curr.next {
		if equal(curr.key.Value) {
			return curr
		}
	}
	return nil
}

func (obj *object) insert(k, v *Term) {
	hash := k.Hash()
	head := obj.elems[hash]
	// This `equal` utility is duplicated and manually inlined a number of
	// time in this file.  Inlining it avoids heap allocations, so it makes
	// a big performance difference: some operations like lookup become twice
	// as slow without it.
	var equal func(v Value) bool

	switch x := k.Value.(type) {
	case Null, Boolean, String, Var:
		equal = func(y Value) bool { return x == y }
	case Number:
		if xi, err := json.Number(x).Int64(); err == nil {
			equal = func(y Value) bool {
				if y, ok := y.(Number); ok {
					if yi, err := json.Number(y).Int64(); err == nil {
						return xi == yi
					}
				}

				return false
			}
			break
		}

		// We use big.Rat for comparing big numbers.
		// It replaces big.Float due to following reason:
		// big.Float comes with a default precision of 64, and setting a
		// larger precision results in more memory being allocated
		// (regardless of the actual number we are parsing with SetString).
		//
		// Note: If we're so close to zero that big.Float says we are zero, do
		// *not* big.Rat).SetString on the original string it'll potentially
		// take very long.
		var a *big.Rat
		fa, ok := new(big.Float).SetString(string(x))
		if !ok {
			panic("illegal value")
		}
		if fa.IsInt() {
			if i, _ := fa.Int64(); i == 0 {
				a = new(big.Rat).SetInt64(0)
			}
		}
		if a == nil {
			a, ok = new(big.Rat).SetString(string(x))
			if !ok {
				panic("illegal value")
			}
		}

		equal = func(b Value) bool {
			if bNum, ok := b.(Number); ok {
				var b *big.Rat
				fb, ok := new(big.Float).SetString(string(bNum))
				if !ok {
					panic("illegal value")
				}
				if fb.IsInt() {
					if i, _ := fb.Int64(); i == 0 {
						b = new(big.Rat).SetInt64(0)
					}
				}
				if b == nil {
					b, ok = new(big.Rat).SetString(string(bNum))
					if !ok {
						panic("illegal value")
					}
				}

				return a.Cmp(b) == 0
			}

			return false
		}
	default:
		equal = func(y Value) bool { return Compare(x, y) == 0 }
	}

	for curr := head; curr != nil; curr = curr.next {
		if equal(curr.key.Value) {
			// The ground bit of the value may change in
			// replace, hence adjust the counter per old
			// and new value.

			if curr.value.IsGround() {
				obj.ground--
			}
			if v.IsGround() {
				obj.ground++
			}

			curr.value = v
			obj.hash = 0
			return
		}
	}
	elem := &objectElem{
		key:   k,
		value: v,
		next:  head,
	}
	obj.elems[hash] = elem
	i := sort.Search(len(obj.keys), func(i int) bool { return Compare(elem.key, obj.keys[i].key) < 0 })
	if i < len(obj.keys) {
		// insert at position `i`:
		obj.keys = append(obj.keys, nil)   // add some space
		copy(obj.keys[i+1:], obj.keys[i:]) // move things over
		obj.keys[i] = elem                 // drop it in position
	} else {
		obj.keys = append(obj.keys, elem)
	}
	obj.hash = 0

	if k.IsGround() {
		obj.ground++
	}
	if v.IsGround() {
		obj.ground++
	}
}

func filterObject(o Value, filter Value) (Value, error) {
	if filter.Compare(Null{}) == 0 {
		return o, nil
	}

	filteredObj, ok := filter.(*object)
	if !ok {
		return nil, fmt.Errorf("invalid filter value %q, expected an object", filter)
	}

	switch v := o.(type) {
	case String, Number, Boolean, Null:
		return o, nil
	case *Array:
		values := NewArray()
		for i := 0; i < v.Len(); i++ {
			subFilter := filteredObj.Get(StringTerm(strconv.Itoa(i)))
			if subFilter != nil {
				filteredValue, err := filterObject(v.Elem(i).Value, subFilter.Value)
				if err != nil {
					return nil, err
				}
				values = values.Append(NewTerm(filteredValue))
			}
		}
		return values, nil
	case Set:
		values := NewSet()
		err := v.Iter(func(t *Term) error {
			if filteredObj.Get(t) != nil {
				filteredValue, err := filterObject(t.Value, filteredObj.Get(t).Value)
				if err != nil {
					return err
				}
				values.Add(NewTerm(filteredValue))
			}
			return nil
		})
		return values, err
	case *object:
		values := NewObject()

		iterObj := v
		other := filteredObj
		if v.Len() < filteredObj.Len() {
			iterObj = filteredObj
			other = v
		}

		err := iterObj.Iter(func(key *Term, value *Term) error {
			if other.Get(key) != nil {
				filteredValue, err := filterObject(v.Get(key).Value, filteredObj.Get(key).Value)
				if err != nil {
					return err
				}
				values.Insert(key, NewTerm(filteredValue))
			}
			return nil
		})
		return values, err
	default:
		return nil, fmt.Errorf("invalid object value type %q", v)
	}
}

// ArrayComprehension represents an array comprehension as defined in the language.
type ArrayComprehension struct {
	Term *Term `json:"term"`
	Body Body  `json:"body"`
}

// ArrayComprehensionTerm creates a new Term with an ArrayComprehension value.
func ArrayComprehensionTerm(term *Term, body Body) *Term {
	return &Term{
		Value: &ArrayComprehension{
			Term: term,
			Body: body,
		},
	}
}

// Copy returns a deep copy of ac.
func (ac *ArrayComprehension) Copy() *ArrayComprehension {
	cpy := *ac
	cpy.Body = ac.Body.Copy()
	cpy.Term = ac.Term.Copy()
	return &cpy
}

// Equal returns true if ac is equal to other.
func (ac *ArrayComprehension) Equal(other Value) bool {
	return Compare(ac, other) == 0
}

// Compare compares ac to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (ac *ArrayComprehension) Compare(other Value) int {
	return Compare(ac, other)
}

// Find returns the current value or a not found error.
func (ac *ArrayComprehension) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return ac, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code of the Value.
func (ac *ArrayComprehension) Hash() int {
	return ac.Term.Hash() + ac.Body.Hash()
}

// IsGround returns true if the Term and Body are ground.
func (ac *ArrayComprehension) IsGround() bool {
	return ac.Term.IsGround() && ac.Body.IsGround()
}

func (ac *ArrayComprehension) String() string {
	return "[" + ac.Term.String() + " | " + ac.Body.String() + "]"
}

// ObjectComprehension represents an object comprehension as defined in the language.
type ObjectComprehension struct {
	Key   *Term `json:"key"`
	Value *Term `json:"value"`
	Body  Body  `json:"body"`
}

// ObjectComprehensionTerm creates a new Term with an ObjectComprehension value.
func ObjectComprehensionTerm(key, value *Term, body Body) *Term {
	return &Term{
		Value: &ObjectComprehension{
			Key:   key,
			Value: value,
			Body:  body,
		},
	}
}

// Copy returns a deep copy of oc.
func (oc *ObjectComprehension) Copy() *ObjectComprehension {
	cpy := *oc
	cpy.Body = oc.Body.Copy()
	cpy.Key = oc.Key.Copy()
	cpy.Value = oc.Value.Copy()
	return &cpy
}

// Equal returns true if oc is equal to other.
func (oc *ObjectComprehension) Equal(other Value) bool {
	return Compare(oc, other) == 0
}

// Compare compares oc to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (oc *ObjectComprehension) Compare(other Value) int {
	return Compare(oc, other)
}

// Find returns the current value or a not found error.
func (oc *ObjectComprehension) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return oc, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code of the Value.
func (oc *ObjectComprehension) Hash() int {
	return oc.Key.Hash() + oc.Value.Hash() + oc.Body.Hash()
}

// IsGround returns true if the Key, Value and Body are ground.
func (oc *ObjectComprehension) IsGround() bool {
	return oc.Key.IsGround() && oc.Value.IsGround() && oc.Body.IsGround()
}

func (oc *ObjectComprehension) String() string {
	return "{" + oc.Key.String() + ": " + oc.Value.String() + " | " + oc.Body.String() + "}"
}

// SetComprehension represents a set comprehension as defined in the language.
type SetComprehension struct {
	Term *Term `json:"term"`
	Body Body  `json:"body"`
}

// SetComprehensionTerm creates a new Term with an SetComprehension value.
func SetComprehensionTerm(term *Term, body Body) *Term {
	return &Term{
		Value: &SetComprehension{
			Term: term,
			Body: body,
		},
	}
}

// Copy returns a deep copy of sc.
func (sc *SetComprehension) Copy() *SetComprehension {
	cpy := *sc
	cpy.Body = sc.Body.Copy()
	cpy.Term = sc.Term.Copy()
	return &cpy
}

// Equal returns true if sc is equal to other.
func (sc *SetComprehension) Equal(other Value) bool {
	return Compare(sc, other) == 0
}

// Compare compares sc to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (sc *SetComprehension) Compare(other Value) int {
	return Compare(sc, other)
}

// Find returns the current value or a not found error.
func (sc *SetComprehension) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return sc, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code of the Value.
func (sc *SetComprehension) Hash() int {
	return sc.Term.Hash() + sc.Body.Hash()
}

// IsGround returns true if the Term and Body are ground.
func (sc *SetComprehension) IsGround() bool {
	return sc.Term.IsGround() && sc.Body.IsGround()
}

func (sc *SetComprehension) String() string {
	return "{" + sc.Term.String() + " | " + sc.Body.String() + "}"
}

// Call represents as function call in the language.
type Call []*Term

// CallTerm returns a new Term with a Call value defined by terms. The first
// term is the operator and the rest are operands.
func CallTerm(terms ...*Term) *Term {
	return NewTerm(Call(terms))
}

// Copy returns a deep copy of c.
func (c Call) Copy() Call {
	return termSliceCopy(c)
}

// Compare compares c to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (c Call) Compare(other Value) int {
	return Compare(c, other)
}

// Find returns the current value or a not found error.
func (c Call) Find(Ref) (Value, error) {
	return nil, errFindNotFound
}

// Hash returns the hash code for the Value.
func (c Call) Hash() int {
	return termSliceHash(c)
}

// IsGround returns true if the Value is ground.
func (c Call) IsGround() bool {
	return termSliceIsGround(c)
}

// MakeExpr returns an ew Expr from this call.
func (c Call) MakeExpr(output *Term) *Expr {
	terms := []*Term(c)
	return NewExpr(append(terms, output))
}

func (c Call) String() string {
	args := make([]string, len(c)-1)
	for i := 1; i < len(c); i++ {
		args[i-1] = c[i].String()
	}
	return fmt.Sprintf("%v(%v)", c[0], strings.Join(args, ", "))
}

func termSliceCopy(a []*Term) []*Term {
	cpy := make([]*Term, len(a))
	for i := range a {
		cpy[i] = a[i].Copy()
	}
	return cpy
}

func termSliceEqual(a, b []*Term) bool {
	if len(a) == len(b) {
		for i := range a {
			if !a[i].Equal(b[i]) {
				return false
			}
		}
		return true
	}
	return false
}

func termSliceHash(a []*Term) int {
	var hash int
	for _, v := range a {
		hash += v.Value.Hash()
	}
	return hash
}

func termSliceIsGround(a []*Term) bool {
	for _, v := range a {
		if !v.IsGround() {
			return false
		}
	}
	return true
}

// NOTE(tsandall): The unmarshalling errors in these functions are not
// helpful for callers because they do not identify the source of the
// unmarshalling error. Because OPA doesn't accept JSON describing ASTs
// from callers, this is acceptable (for now). If that changes in the future,
// the error messages should be revisited. The current approach focuses
// on the happy path and treats all errors the same. If better error
// reporting is needed, the error paths will need to be fleshed out.

func unmarshalBody(b []interface{}) (Body, error) {
	buf := Body{}
	for _, e := range b {
		if m, ok := e.(map[string]interface{}); ok {
			expr := &Expr{}
			if err := unmarshalExpr(expr, m); err == nil {
				buf = append(buf, expr)
				continue
			}
		}
		goto unmarshal_error
	}
	return buf, nil
unmarshal_error:
	return nil, fmt.Errorf("ast: unable to unmarshal body")
}

func unmarshalExpr(expr *Expr, v map[string]interface{}) error {
	if x, ok := v["negated"]; ok {
		if b, ok := x.(bool); ok {
			expr.Negated = b
		} else {
			return fmt.Errorf("ast: unable to unmarshal negated field with type: %T (expected true or false)", v["negated"])
		}
	}
	if err := unmarshalExprIndex(expr, v); err != nil {
		return err
	}
	switch ts := v["terms"].(type) {
	case map[string]interface{}:
		t, err := unmarshalTerm(ts)
		if err != nil {
			return err
		}
		expr.Terms = t
	case []interface{}:
		terms, err := unmarshalTermSlice(ts)
		if err != nil {
			return err
		}
		expr.Terms = terms
	default:
		return fmt.Errorf(`ast: unable to unmarshal terms field with type: %T (expected {"value": ..., "type": ...} or [{"value": ..., "type": ...}, ...])`, v["terms"])
	}
	if x, ok := v["with"]; ok {
		if sl, ok := x.([]interface{}); ok {
			ws := make([]*With, len(sl))
			for i := range sl {
				var err error
				ws[i], err = unmarshalWith(sl[i])
				if err != nil {
					return err
				}
			}
			expr.With = ws
		}
	}
	return nil
}

func unmarshalExprIndex(expr *Expr, v map[string]interface{}) error {
	if x, ok := v["index"]; ok {
		if n, ok := x.(json.Number); ok {
			i, err := n.Int64()
			if err == nil {
				expr.Index = int(i)
				return nil
			}
		}
	}
	return fmt.Errorf("ast: unable to unmarshal index field with type: %T (expected integer)", v["index"])
}

func unmarshalTerm(m map[string]interface{}) (*Term, error) {
	v, err := unmarshalValue(m)
	if err != nil {
		return nil, err
	}
	return &Term{Value: v}, nil
}

func unmarshalTermSlice(s []interface{}) ([]*Term, error) {
	buf := []*Term{}
	for _, x := range s {
		if m, ok := x.(map[string]interface{}); ok {
			if t, err := unmarshalTerm(m); err == nil {
				buf = append(buf, t)
				continue
			} else {
				return nil, err
			}
		}
		return nil, fmt.Errorf("ast: unable to unmarshal term")
	}
	return buf, nil
}

func unmarshalTermSliceValue(d map[string]interface{}) ([]*Term, error) {
	if s, ok := d["value"].([]interface{}); ok {
		return unmarshalTermSlice(s)
	}
	return nil, fmt.Errorf(`ast: unable to unmarshal term (expected {"value": [...], "type": ...} where type is one of: ref, array, or set)`)
}

func unmarshalWith(i interface{}) (*With, error) {
	if m, ok := i.(map[string]interface{}); ok {
		tgt, _ := m["target"].(map[string]interface{})
		target, err := unmarshalTerm(tgt)
		if err == nil {
			val, _ := m["value"].(map[string]interface{})
			value, err := unmarshalTerm(val)
			if err == nil {
				return &With{
					Target: target,
					Value:  value,
				}, nil
			}
			return nil, err
		}
		return nil, err
	}
	return nil, fmt.Errorf(`ast: unable to unmarshal with modifier (expected {"target": {...}, "value": {...}})`)
}

func unmarshalValue(d map[string]interface{}) (Value, error) {
	v := d["value"]
	switch d["type"] {
	case "null":
		return Null{}, nil
	case "boolean":
		if b, ok := v.(bool); ok {
			return Boolean(b), nil
		}
	case "number":
		if n, ok := v.(json.Number); ok {
			return Number(n), nil
		}
	case "string":
		if s, ok := v.(string); ok {
			return String(s), nil
		}
	case "var":
		if s, ok := v.(string); ok {
			return Var(s), nil
		}
	case "ref":
		if s, err := unmarshalTermSliceValue(d); err == nil {
			return Ref(s), nil
		}
	case "array":
		if s, err := unmarshalTermSliceValue(d); err == nil {
			return NewArray(s...), nil
		}
	case "set":
		if s, err := unmarshalTermSliceValue(d); err == nil {
			set := NewSet()
			for _, x := range s {
				set.Add(x)
			}
			return set, nil
		}
	case "object":
		if s, ok := v.([]interface{}); ok {
			buf := NewObject()
			for _, x := range s {
				if i, ok := x.([]interface{}); ok && len(i) == 2 {
					p, err := unmarshalTermSlice(i)
					if err == nil {
						buf.Insert(p[0], p[1])
						continue
					}
				}
				goto unmarshal_error
			}
			return buf, nil
		}
	case "arraycomprehension", "setcomprehension":
		if m, ok := v.(map[string]interface{}); ok {
			t, ok := m["term"].(map[string]interface{})
			if !ok {
				goto unmarshal_error
			}

			term, err := unmarshalTerm(t)
			if err != nil {
				goto unmarshal_error
			}

			b, ok := m["body"].([]interface{})
			if !ok {
				goto unmarshal_error
			}

			body, err := unmarshalBody(b)
			if err != nil {
				goto unmarshal_error
			}

			if d["type"] == "arraycomprehension" {
				return &ArrayComprehension{Term: term, Body: body}, nil
			}
			return &SetComprehension{Term: term, Body: body}, nil
		}
	case "objectcomprehension":
		if m, ok := v.(map[string]interface{}); ok {
			k, ok := m["key"].(map[string]interface{})
			if !ok {
				goto unmarshal_error
			}

			key, err := unmarshalTerm(k)
			if err != nil {
				goto unmarshal_error
			}

			v, ok := m["value"].(map[string]interface{})
			if !ok {
				goto unmarshal_error
			}

			value, err := unmarshalTerm(v)
			if err != nil {
				goto unmarshal_error
			}

			b, ok := m["body"].([]interface{})
			if !ok {
				goto unmarshal_error
			}

			body, err := unmarshalBody(b)
			if err != nil {
				goto unmarshal_error
			}

			return &ObjectComprehension{Key: key, Value: value, Body: body}, nil
		}
	case "call":
		if s, err := unmarshalTermSliceValue(d); err == nil {
			return Call(s), nil
		}
	}
unmarshal_error:
	return nil, fmt.Errorf("ast: unable to unmarshal term")
}
