package terraform

import (
	"fmt"
	"io/fs"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"

	"github.com/aquasecurity/trivy/pkg/iac/terraform/context"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Attribute struct {
	hclAttribute *hcl.Attribute
	module       string
	ctx          *context.Context
	metadata     iacTypes.Metadata
	reference    Reference
}

func (a *Attribute) DecodeVarType() (cty.Type, *typeexpr.Defaults, error) {
	// Special-case the shortcuts for list(any) and map(any) which aren't hcl.
	switch hcl.ExprAsKeyword(a.hclAttribute.Expr) {
	case "list":
		return cty.List(cty.DynamicPseudoType), nil, nil
	case "map":
		return cty.Map(cty.DynamicPseudoType), nil, nil
	}

	t, def, diag := typeexpr.TypeConstraintWithDefaults(a.hclAttribute.Expr)
	if diag.HasErrors() {
		return cty.NilType, nil, diag
	}
	return t, def, nil
}

func NewAttribute(attr *hcl.Attribute, ctx *context.Context, module string, parent iacTypes.Metadata, parentRef Reference, moduleSource string, moduleFS fs.FS) *Attribute {
	rng := iacTypes.NewRange(
		attr.Range.Filename,
		attr.Range.Start.Line,
		attr.Range.End.Line,
		moduleSource,
		moduleFS,
	)
	reference := extendReference(parentRef, attr.Name)
	metadata := iacTypes.NewMetadata(rng, reference.String())
	return &Attribute{
		hclAttribute: attr,
		ctx:          ctx,
		module:       module,
		metadata:     metadata.WithParent(parent),
		reference:    reference,
	}
}

func (a *Attribute) GetMetadata() iacTypes.Metadata {
	return a.metadata
}

func (a *Attribute) GetRawValue() any {
	switch typ := a.Type(); typ {
	case cty.String:
		return a.Value().AsString()
	case cty.Bool:
		return a.Value().True()
	case cty.Number:
		float, _ := a.Value().AsBigFloat().Float64()
		return float
	default:
		switch {
		case typ.IsTupleType(), typ.IsListType(), typ.IsSetType():
			values := a.Value().AsValueSlice()
			if len(values) == 0 {
				return []string{}
			}
			switch values[0].Type() {
			case cty.String:
				var output []string
				for _, value := range values {
					output = append(output, value.AsString())
				}
				return output
			case cty.Number:
				var output []float64
				for _, value := range values {
					bf := value.AsBigFloat()
					f, _ := bf.Float64()
					output = append(output, f)
				}
				return output
			case cty.Bool:
				var output []bool
				for _, value := range values {
					output = append(output, value.True())
				}
				return output
			}
		}
	}
	return nil
}

func (a *Attribute) AsBytesValueOrDefault(defaultValue []byte, parent *Block) iacTypes.BytesValue {
	if a.IsNil() {
		return iacTypes.BytesDefault(defaultValue, parent.GetMetadata())
	}
	if a.IsNotResolvable() || !a.IsString() {
		return iacTypes.BytesUnresolvable(a.GetMetadata())
	}
	return iacTypes.BytesExplicit(
		[]byte(a.Value().AsString()),
		a.GetMetadata(),
	)
}

func (a *Attribute) AsStringValueOrDefault(defaultValue string, parent *Block) iacTypes.StringValue {
	if a.IsNil() {
		return iacTypes.StringDefault(defaultValue, parent.GetMetadata())
	}
	if a.IsNotResolvable() || !a.IsString() {
		return iacTypes.StringUnresolvable(a.GetMetadata())
	}
	return iacTypes.StringExplicit(
		a.Value().AsString(),
		a.GetMetadata(),
	)
}

func (a *Attribute) AsStringValueSliceOrEmpty() (stringValues []iacTypes.StringValue) {
	if a.IsNil() {
		return stringValues
	}
	return a.AsStringValues()
}

func (a *Attribute) AsStringValuesOrDefault(parent *Block, defaults ...string) []iacTypes.StringValue {
	if a.IsNil() {
		res := make(iacTypes.StringValueList, 0, len(defaults))
		for _, def := range defaults {
			res = append(res, iacTypes.StringDefault(def, parent.GetMetadata()))
		}
		return res
	}
	return a.AsStringValues()
}

func (a *Attribute) AsBoolValueOrDefault(defaultValue bool, parent *Block) iacTypes.BoolValue {
	if a.IsNil() {
		return iacTypes.BoolDefault(defaultValue, parent.GetMetadata())
	}
	if a.IsNotResolvable() || !a.IsBool() {
		return iacTypes.BoolUnresolvable(a.GetMetadata())
	}
	return iacTypes.BoolExplicit(
		a.IsTrue(),
		a.GetMetadata(),
	)
}

func (a *Attribute) AsIntValueOrDefault(defaultValue int, parent *Block) iacTypes.IntValue {
	if a.IsNil() {
		return iacTypes.IntDefault(defaultValue, parent.GetMetadata())
	}
	if a.IsNotResolvable() || !a.IsNumber() {
		return iacTypes.IntUnresolvable(a.GetMetadata())
	}
	flt := a.AsNumber()
	return iacTypes.IntExplicit(
		int(flt),
		a.GetMetadata(),
	)
}

func (a *Attribute) IsLiteral() bool {
	if a == nil {
		return false
	}
	return len(a.hclAttribute.Expr.Variables()) == 0
}

func (a *Attribute) IsResolvable() bool {
	if a == nil {
		return false
	}
	return a.Value() != cty.NilVal && a.Value().IsKnown()
}

func (a *Attribute) IsNotResolvable() bool {
	return !a.IsResolvable()
}

func (a *Attribute) Type() cty.Type {
	if a == nil {
		return cty.NilType
	}
	return a.Value().Type()
}

func (a *Attribute) IsIterable() bool {
	if a == nil {
		return false
	}
	return a.Value().Type().IsListType() || a.Value().Type().IsCollectionType() || a.Value().Type().IsObjectType() || a.Value().Type().IsMapType() || a.Value().Type().IsListType() || a.Value().Type().IsSetType() || a.Value().Type().IsTupleType()
}

func (a *Attribute) Each(f func(key cty.Value, val cty.Value)) error {
	if a == nil {
		return nil
	}
	var outerErr error
	defer func() {
		if err := recover(); err != nil {
			outerErr = fmt.Errorf("go-cty bug detected - cannot call ForEachElement: %s", err)
		}
	}()
	val := a.Value()
	val.ForEachElement(func(key cty.Value, val cty.Value) (stop bool) {
		f(key, val)
		return false
	})
	return outerErr
}

func (a *Attribute) IsString() bool {
	if a == nil {
		return false
	}
	return !a.Value().IsNull() && a.Value().IsKnown() && a.Value().Type() == cty.String
}

func (a *Attribute) IsMapOrObject() bool {
	if a == nil || a.Value().IsNull() || !a.Value().IsKnown() {
		return false
	}

	return a.Value().Type().IsObjectType() || a.Value().Type().IsMapType()
}

func (a *Attribute) IsNumber() bool {
	if a != nil && !a.Value().IsNull() && a.Value().IsKnown() {
		if a.Value().Type() == cty.Number {
			return true
		}
		if a.Value().Type() == cty.String {
			_, err := strconv.ParseFloat(a.Value().AsString(), 64)
			return err == nil
		}
	}

	return false
}

func (a *Attribute) IsBool() bool {
	if a == nil {
		return false
	}
	switch a.Value().Type() {
	case cty.Bool, cty.Number:
		return true
	case cty.String:
		val := a.Value().AsString()
		val = strings.Trim(val, "\"")
		return strings.EqualFold(val, "false") || strings.EqualFold(val, "true")
	}
	return false
}

func (a *Attribute) Value() (ctyVal cty.Value) {
	if a == nil {
		return cty.NilVal
	}
	defer func() {
		if err := recover(); err != nil {
			ctyVal = cty.NilVal
		}
	}()
	ctyVal, _ = a.hclAttribute.Expr.Value(a.ctx.Inner())
	if !ctyVal.IsKnown() || ctyVal.IsNull() {
		return cty.NilVal
	}
	return ctyVal
}

// Allows a null value for a variable https://developer.hashicorp.com/terraform/language/expressions/types#null
func (a *Attribute) NullableValue() (ctyVal cty.Value) {
	if a == nil {
		return cty.NilVal
	}
	defer func() {
		if err := recover(); err != nil {
			ctyVal = cty.NilVal
		}
	}()
	ctyVal, _ = a.hclAttribute.Expr.Value(a.ctx.Inner())
	if !ctyVal.IsKnown() {
		return cty.NilVal
	}
	return ctyVal
}

func (a *Attribute) Name() string {
	if a == nil {
		return ""
	}
	return a.hclAttribute.Name
}

func (a *Attribute) AsStringValues() iacTypes.StringValueList {
	if a == nil {
		return nil
	}
	return a.getStringValues(a.hclAttribute.Expr, a.ctx.Inner())
}

// nolint
func (a *Attribute) getStringValues(expr hcl.Expression, ctx *hcl.EvalContext) (results []iacTypes.StringValue) {

	defer func() {
		if err := recover(); err != nil {
			results = []iacTypes.StringValue{iacTypes.StringUnresolvable(a.metadata)}
		}
	}()

	switch t := expr.(type) {
	case *hclsyntax.TupleConsExpr:
		for _, expr := range t.Exprs {
			val, err := expr.Value(a.ctx.Inner())
			if err != nil {
				results = append(results, iacTypes.StringUnresolvable(a.metadata))
				continue
			}
			results = append(results, a.valueToString(val))
		}
	case *hclsyntax.FunctionCallExpr, *hclsyntax.ConditionalExpr:
		subVal, err := t.Value(ctx)
		if err != nil {
			return append(results, iacTypes.StringUnresolvable(a.metadata))
		}
		return a.valueToStrings(subVal)
	case *hclsyntax.LiteralValueExpr:
		return a.valueToStrings(t.Val)
	case *hclsyntax.TemplateExpr:
		// walk the parts of the expression to ensure that it has a literal value
		for _, p := range t.Parts {
			val, err := p.Value(a.ctx.Inner())
			if err != nil {
				results = append(results, iacTypes.StringUnresolvable(a.metadata))
				continue
			}
			value := a.valueToString(val)
			results = append(results, value)
		}
	case *hclsyntax.ScopeTraversalExpr:
		// handle the case for referencing a data
		if len(t.Variables()) > 0 {
			if t.Variables()[0].RootName() == "data" {
				// we can't resolve data lookups at this time, so make unresolvable
				return append(results, iacTypes.StringUnresolvable(a.metadata))
			}
		}
		subVal, err := t.Value(ctx)
		if err != nil {
			return append(results, iacTypes.StringUnresolvable(a.metadata))
		}
		return a.valueToStrings(subVal)
	default:
		val, err := t.Value(a.ctx.Inner())
		if err != nil {
			return append(results, iacTypes.StringUnresolvable(a.metadata))
		}
		results = a.valueToStrings(val)
	}
	return results
}

func (a *Attribute) valueToStrings(value cty.Value) (results []iacTypes.StringValue) {
	defer func() {
		if err := recover(); err != nil {
			results = []iacTypes.StringValue{iacTypes.StringUnresolvable(a.metadata)}
		}
	}()
	if value.IsNull() {
		return []iacTypes.StringValue{iacTypes.StringUnresolvable(a.metadata)}
	}
	if !value.IsKnown() {
		return []iacTypes.StringValue{iacTypes.StringUnresolvable(a.metadata)}
	}
	if value.Type().IsListType() || value.Type().IsTupleType() || value.Type().IsSetType() {
		for _, val := range value.AsValueSlice() {
			results = append(results, a.valueToString(val))
		}
	}
	return results
}

func (a *Attribute) valueToString(value cty.Value) (result iacTypes.StringValue) {
	defer func() {
		if err := recover(); err != nil {
			result = iacTypes.StringUnresolvable(a.metadata)
		}
	}()

	result = iacTypes.StringUnresolvable(a.metadata)

	if value.IsNull() || !value.IsKnown() {
		return result
	}

	switch value.Type() {
	case cty.String:
		return iacTypes.String(value.AsString(), a.metadata)
	default:
		return result
	}
}

func (a *Attribute) listContains(val cty.Value, stringToLookFor string, ignoreCase bool) bool {
	if a == nil {
		return false
	}

	valueSlice := val.AsValueSlice()
	for _, value := range valueSlice {
		if value.IsNull() || !value.IsKnown() {
			// there is nothing we can do with this value
			continue
		}
		stringToTest := value
		if value.Type().IsObjectType() || value.Type().IsMapType() {
			valueMap := value.AsValueMap()
			stringToTest = valueMap["key"]
		}
		if value.Type().HasDynamicTypes() {
			for _, extracted := range a.extractListValues() {
				if extracted == stringToLookFor {
					return true
				}
			}
			return false
		}
		if !value.IsKnown() {
			continue
		}
		if ignoreCase && strings.EqualFold(stringToTest.AsString(), stringToLookFor) {
			return true
		}
		if stringToTest.AsString() == stringToLookFor {
			return true
		}
	}
	return false
}

func (a *Attribute) extractListValues() []string {
	var values []string
	if a.hclAttribute == nil || a.hclAttribute.Expr == nil || a.hclAttribute.Expr.Variables() == nil {
		return values
	}
	for _, v := range a.hclAttribute.Expr.Variables() {
		values = append(values, v.RootName())
	}
	return values
}

func (a *Attribute) mapContains(checkValue any, val cty.Value) bool {
	if a == nil {
		return false
	}
	valueMap := val.AsValueMap()
	switch t := checkValue.(type) {
	case map[any]any:
		for k, v := range t {
			for key, value := range valueMap {
				rawValue := getRawValue(value)
				if key == k && evaluate(v, rawValue) {
					return true
				}
			}
		}
		return false
	case map[string]any:
		for k, v := range t {
			for key, value := range valueMap {
				rawValue := getRawValue(value)
				if key == k && evaluate(v, rawValue) {
					return true
				}
			}
		}
		return false
	default:
		for key := range valueMap {
			if key == checkValue {
				return true
			}
		}
		return false
	}
}

func (a *Attribute) NotContains(checkValue any, equalityOptions ...EqualityOption) bool {
	return !a.Contains(checkValue, equalityOptions...)
}

func (a *Attribute) Contains(checkValue any, equalityOptions ...EqualityOption) bool {
	if a == nil {
		return false
	}
	ignoreCase := false
	for _, option := range equalityOptions {
		if option == IgnoreCase {
			ignoreCase = true
		}
	}
	val := a.Value()
	if val.IsNull() {
		return false
	}

	if val.Type().IsObjectType() || val.Type().IsMapType() {
		return a.mapContains(checkValue, val)
	}

	stringToLookFor := fmt.Sprintf("%v", checkValue)

	if val.Type().IsListType() || val.Type().IsTupleType() {
		return a.listContains(val, stringToLookFor, ignoreCase)
	}

	if ignoreCase && containsIgnoreCase(val.AsString(), stringToLookFor) {
		return true
	}

	return strings.Contains(val.AsString(), stringToLookFor)
}

func (a *Attribute) OnlyContains(checkValue any) bool {
	if a == nil {
		return false
	}
	val := a.Value()
	if val.IsNull() {
		return false
	}

	checkSlice, ok := checkValue.([]any)
	if !ok {
		return false
	}

	if val.Type().IsListType() || val.Type().IsTupleType() {
		for _, value := range val.AsValueSlice() {
			found := false
			for _, cVal := range checkSlice {
				switch t := cVal.(type) {
				case string:
					if t == value.AsString() {
						found = true
						break
					}
				case bool:
					if t == value.True() {
						found = true
						break
					}
				case int, int8, int16, int32, int64:
					i, _ := value.AsBigFloat().Int64()
					if t == i {
						found = true
						break
					}
				case float32, float64:
					f, _ := value.AsBigFloat().Float64()
					if t == f {
						found = true
						break
					}
				}

			}
			if !found {
				return false
			}
		}
		return true
	}

	return false
}

func containsIgnoreCase(left, substring string) bool {
	return strings.Contains(strings.ToLower(left), strings.ToLower(substring))
}

func (a *Attribute) StartsWith(prefix any) bool {
	if a == nil {
		return false
	}
	if a.Value().Type() == cty.String {
		return strings.HasPrefix(a.Value().AsString(), fmt.Sprintf("%v", prefix))
	}
	return false
}

func (a *Attribute) EndsWith(suffix any) bool {
	if a == nil {
		return false
	}
	if a.Value().Type() == cty.String {
		return strings.HasSuffix(a.Value().AsString(), fmt.Sprintf("%v", suffix))
	}
	return false
}

type EqualityOption int

const (
	IgnoreCase EqualityOption = iota
)

func (a *Attribute) Equals(checkValue any, equalityOptions ...EqualityOption) bool {
	if a == nil {
		return false
	}
	if a.Value().Type() == cty.String {
		for _, option := range equalityOptions {
			if option == IgnoreCase {
				return strings.EqualFold(strings.ToLower(a.Value().AsString()), strings.ToLower(fmt.Sprintf("%v", checkValue)))
			}
		}
		result := strings.EqualFold(a.Value().AsString(), fmt.Sprintf("%v", checkValue))
		return result
	}
	if a.Value().Type() == cty.Bool {
		return a.Value().True() == checkValue
	}
	if a.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			return false
		}
		return a.Value().RawEquals(checkNumber)
	}

	return false
}

func (a *Attribute) NotEqual(checkValue any, equalityOptions ...EqualityOption) bool {
	return !a.Equals(checkValue, equalityOptions...)
}

func (a *Attribute) RegexMatches(re regexp.Regexp) bool {
	if a == nil {
		return false
	}
	if a.Value().Type() == cty.String {
		match := re.MatchString(a.Value().AsString())
		return match
	}
	return false
}

func (a *Attribute) IsNotAny(options ...any) bool {
	return !a.IsAny(options...)
}

func (a *Attribute) IsAny(options ...any) bool {
	if a == nil {
		return false
	}
	if a.Value().Type() == cty.String {
		value := a.Value().AsString()
		for _, option := range options {
			if option == value {
				return true
			}
		}
	}
	if a.Value().Type() == cty.Number {
		for _, option := range options {
			checkValue, err := gocty.ToCtyValue(option, cty.Number)
			if err != nil {
				return false
			}
			if a.Value().RawEquals(checkValue) {
				return true
			}
		}
	}
	return false
}

func (a *Attribute) IsNone(options ...any) bool {
	if a == nil {
		return false
	}
	if a.Value().Type() == cty.String {
		for _, option := range options {
			if option == a.Value().AsString() {
				return false
			}
		}
	}
	if a.Value().Type() == cty.Number {
		for _, option := range options {
			checkValue, err := gocty.ToCtyValue(option, cty.Number)
			if err != nil {
				return false
			}
			if a.Value().RawEquals(checkValue) {
				return false
			}

		}
	}

	return true
}

func (a *Attribute) IsTrue() bool {
	if a == nil {
		return false
	}
	val := a.Value()
	switch val.Type() {
	case cty.Bool:
		return val.True()
	case cty.String:
		val := val.AsString()
		val = strings.Trim(val, "\"")
		return strings.EqualFold(val, "true")
	case cty.Number:
		val := val.AsBigFloat()
		f, _ := val.Float64()
		return f > 0
	}
	return false
}

func (a *Attribute) IsFalse() bool {
	if a == nil {
		return false
	}
	switch a.Value().Type() {
	case cty.Bool:
		return a.Value().False()
	case cty.String:
		val := a.Value().AsString()
		val = strings.Trim(val, "\"")
		return strings.EqualFold(val, "false")
	case cty.Number:
		val := a.Value().AsBigFloat()
		f, _ := val.Float64()
		return f == 0
	}
	return false
}

func (a *Attribute) IsEmpty() bool {
	if a == nil {
		return false
	}
	if a.Value().Type() == cty.String {
		return a.Value().AsString() == ""
	}
	if a.Type().IsListType() || a.Type().IsTupleType() {
		return len(a.Value().AsValueSlice()) == 0
	}
	if a.Type().IsMapType() || a.Type().IsObjectType() {
		return len(a.Value().AsValueMap()) == 0
	}
	if a.Value().Type() == cty.Number {
		// a number can't ever be empty
		return false
	}
	if a.Value().IsNull() {
		return a.isNullAttributeEmpty()
	}
	return true
}

func (a *Attribute) IsNotEmpty() bool {
	return !a.IsEmpty()
}

func (a *Attribute) isNullAttributeEmpty() bool {
	if a == nil {
		return false
	}
	switch t := a.hclAttribute.Expr.(type) {
	case *hclsyntax.FunctionCallExpr, *hclsyntax.ScopeTraversalExpr,
		*hclsyntax.ConditionalExpr, *hclsyntax.LiteralValueExpr:
		return false
	case *hclsyntax.TemplateExpr:
		// walk the parts of the expression to ensure that it has a literal value
		for _, p := range t.Parts {
			switch pt := p.(type) {
			case *hclsyntax.LiteralValueExpr:
				if pt != nil && !pt.Val.IsNull() {
					return false
				}
			case *hclsyntax.ScopeTraversalExpr:
				return false
			}
		}
	}
	return true
}

func (a *Attribute) MapValue(mapKey string) cty.Value {
	if a == nil {
		return cty.NilVal
	}
	if a.Type().IsObjectType() || a.Type().IsMapType() {
		attrMap := a.Value().AsValueMap()
		for key, value := range attrMap {
			if key == mapKey {
				return value
			}
		}
	}
	return cty.NilVal
}

func (a *Attribute) AsMapValue() iacTypes.MapValue {
	if a.IsNil() || a.IsNotResolvable() || !a.IsMapOrObject() {
		return iacTypes.MapValue{}
	}

	values := make(map[string]string)
	_ = a.Each(func(key, val cty.Value) {
		if key.Type() == cty.String && val.Type() == cty.String {
			values[key.AsString()] = val.AsString()
		}
	})

	return iacTypes.Map(values, a.GetMetadata())
}

func (a *Attribute) LessThan(checkValue any) bool {
	if a == nil {
		return false
	}
	if a.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			return false
		}

		return a.Value().LessThan(checkNumber).True()
	}
	return false
}

func (a *Attribute) LessThanOrEqualTo(checkValue any) bool {
	if a == nil {
		return false
	}
	if a.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			return false
		}

		return a.Value().LessThanOrEqualTo(checkNumber).True()
	}
	return false
}

func (a *Attribute) GreaterThan(checkValue any) bool {
	if a == nil {
		return false
	}
	if a.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			return false
		}

		return a.Value().GreaterThan(checkNumber).True()
	}
	return false
}

func (a *Attribute) GreaterThanOrEqualTo(checkValue any) bool {
	if a == nil {
		return false
	}
	if a.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			return false
		}

		return a.Value().GreaterThanOrEqualTo(checkNumber).True()
	}
	return false
}

func (a *Attribute) IsDataBlockReference() bool {
	if a == nil {
		return false
	}
	if t, ok := a.hclAttribute.Expr.(*hclsyntax.ScopeTraversalExpr); ok {
		split := t.Traversal.SimpleSplit()
		return split.Abs.RootName() == "data"
	}
	return false
}

func createDotReferenceFromTraversal(parentRef string, traversals ...hcl.Traversal) (*Reference, error) {
	var refParts []string
	var key cty.Value
	for _, x := range traversals {
		for _, p := range x {
			switch part := p.(type) {
			case hcl.TraverseRoot:
				refParts = append(refParts, part.Name)
			case hcl.TraverseAttr:
				refParts = append(refParts, part.Name)
			case hcl.TraverseIndex:
				key = part.Key
			}
		}
	}
	ref, err := newReference(refParts, parentRef)
	if err != nil {
		return nil, err
	}
	ref.SetKey(key)
	return ref, nil
}

func (a *Attribute) ReferencesBlock(b *Block) bool {
	if a == nil {
		return false
	}
	for _, ref := range a.AllReferences() {
		if ref.RefersTo(b.reference) {
			return true
		}
	}
	return false
}

// nolint
func (a *Attribute) AllReferences(blocks ...*Block) []*Reference {
	if a == nil {
		return nil
	}
	refs := a.extractReferences()
	for _, block := range blocks {
		for _, ref := range refs {
			if ref.TypeLabel() == "each" && block.HasChild("for_each") {
				refs = append(refs, block.GetAttribute("for_each").AllReferences()...)
			}
		}
	}
	return refs
}

// nolint
func (a *Attribute) referencesFromExpression(expression hcl.Expression) []*Reference {
	var refs []*Reference
	switch t := expression.(type) {
	case *hclsyntax.ConditionalExpr:
		if ref, err := createDotReferenceFromTraversal(a.module, t.TrueResult.Variables()...); err == nil {
			refs = append(refs, ref)
		}
		if ref, err := createDotReferenceFromTraversal(a.module, t.FalseResult.Variables()...); err == nil {
			refs = append(refs, ref)
		}
		if ref, err := createDotReferenceFromTraversal(a.module, t.Condition.Variables()...); err == nil {
			refs = append(refs, ref)
		}
	case *hclsyntax.ScopeTraversalExpr:
		if ref, err := createDotReferenceFromTraversal(a.module, t.Variables()...); err == nil {
			refs = append(refs, ref)
		}
	case *hclsyntax.TemplateWrapExpr:
		refs = a.referencesFromExpression(t.Wrapped)
	case *hclsyntax.TemplateExpr:
		for _, part := range t.Parts {
			ref, err := createDotReferenceFromTraversal(a.module, part.Variables()...)
			if err != nil {
				continue
			}
			refs = append(refs, ref)
		}
	case *hclsyntax.TupleConsExpr:
		for _, v := range t.Variables() {
			if ref, err := createDotReferenceFromTraversal(a.module, v); err == nil {
				refs = append(refs, ref)
			}
		}
	case *hclsyntax.RelativeTraversalExpr:
		switch s := t.Source.(type) {
		case *hclsyntax.IndexExpr:
			if collectionRef, err := createDotReferenceFromTraversal(a.module, s.Collection.Variables()...); err == nil {
				key, _ := s.Key.Value(a.ctx.Inner())
				collectionRef.SetKey(key)
				refs = append(refs, collectionRef)
			}
		default:
			if ref, err := createDotReferenceFromTraversal(a.module, t.Source.Variables()...); err == nil {
				refs = append(refs, ref)
			}
		}
	default:
		if reflect.TypeOf(expression).String() == "*json.expression" {
			if ref, err := createDotReferenceFromTraversal(a.module, expression.Variables()...); err == nil {
				refs = append(refs, ref)
			}
		}
	}
	return refs
}

func (a *Attribute) extractReferences() []*Reference {
	if a == nil {
		return nil
	}
	return a.referencesFromExpression(a.hclAttribute.Expr)
}

func (a *Attribute) IsResourceBlockReference(resourceType string) bool {
	if a == nil {
		return false
	}
	if t, ok := a.hclAttribute.Expr.(*hclsyntax.ScopeTraversalExpr); ok {
		split := t.Traversal.SimpleSplit()
		return split.Abs.RootName() == resourceType
	}
	return false
}

func (a *Attribute) References(r Reference) bool {
	if a == nil {
		return false
	}
	for _, ref := range a.AllReferences() {
		if ref.RefersTo(r) {
			return true
		}
	}
	return false
}

func getRawValue(value cty.Value) any {
	if value.IsNull() || !value.IsKnown() {
		return value
	}

	typeName := value.Type().FriendlyName()

	switch typeName {
	case "string":
		return value.AsString()
	case "number":
		return value.AsBigFloat()
	case "bool":
		return value.True()
	}

	return value
}

func (a *Attribute) IsNil() bool {
	return a == nil
}

func (a *Attribute) IsNotNil() bool {
	return !a.IsNil()
}

func (a *Attribute) HasIntersect(checkValues ...any) bool {
	if !a.Type().IsListType() && !a.Type().IsTupleType() {
		return false
	}

	for _, item := range checkValues {
		if a.Contains(item) {
			return true
		}
	}
	return false

}

func (a *Attribute) AsNumber() float64 {
	if a.Value().Type() == cty.Number {
		v, _ := a.Value().AsBigFloat().Float64()
		return v
	}
	if a.Value().Type() == cty.String {
		v, _ := strconv.ParseFloat(a.Value().AsString(), 64)
		return v
	}
	panic("Attribute is not a number")
}
