package terraform

import (
	"fmt"
	"io/fs"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/gocty"

	"github.com/aquasecurity/trivy/pkg/iac/terraform/context"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
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

func (a *Attribute) HCLAttribute() *hcl.Attribute {
	return a.hclAttribute
}

func (a *Attribute) GetMetadata() iacTypes.Metadata {
	return a.metadata
}

func (a *Attribute) GetRawValue() any {
	return safeOp(a, func(v cty.Value) any {
		switch typ := v.Type(); typ {
		case cty.String:
			return v.AsString()
		case cty.Bool:
			return v.True()
		case cty.Number:
			float, _ := v.AsBigFloat().Float64()
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
	})
}

func (a *Attribute) AsBytesValueOrDefault(defaultValue []byte, parent *Block) iacTypes.BytesValue {
	if a.IsNil() {
		return iacTypes.BytesDefault(defaultValue, parent.GetMetadata())
	}
	if !a.IsResolvable() || !a.IsString() {
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
	if !a.IsResolvable() || !a.IsString() {
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
	if !a.IsResolvable() || !a.IsBool() {
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
	if !a.IsResolvable() || !a.IsNumber() {
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

	ty := a.Value().Type()
	return ty.IsListType() || ty.IsObjectType() || ty.IsMapType() ||
		ty.IsSetType() || ty.IsTupleType()
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
	return safeOp(a, func(v cty.Value) bool {
		return v.Type() == cty.String
	})
}

func (a *Attribute) IsMapOrObject() bool {
	return safeOp(a, func(v cty.Value) bool {
		return v.Type().IsObjectType() || v.Type().IsMapType()
	})
}

func (a *Attribute) IsNumber() bool {
	return safeOp(a, func(v cty.Value) bool {
		switch v.Type() {
		case cty.Number:
			return true
		case cty.String:
			_, err := strconv.ParseFloat(v.AsString(), 64)
			return err == nil
		default:
			return false
		}
	})
}

func (a *Attribute) IsBool() bool {
	return safeOp(a, func(v cty.Value) bool {
		switch v.Type() {
		case cty.Bool, cty.Number:
			return true
		case cty.String:
			val := v.AsString()
			val = strings.Trim(val, "\"")
			return strings.EqualFold(val, "false") || strings.EqualFold(val, "true")
		default:
			return false
		}
	})
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
	if ctyVal.IsNull() {
		return cty.DynamicVal
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
	if !ctyVal.IsKnown() || ctyVal.IsNull() {
		return cty.NullVal(cty.DynamicPseudoType)
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
	if value.IsNull() || !value.IsKnown() {
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

func (a *Attribute) listContains(stringToLookFor string, ignoreCase bool) bool {
	return safeOp(a, func(v cty.Value) bool {
		if !v.Type().IsListType() && !v.Type().IsTupleType() {
			return false
		}

		elems := v.AsValueSlice()
		for _, el := range elems {
			if el.IsNull() || !el.IsKnown() {
				// there is nothing we can do with this value
				continue
			}
			stringToTest := el
			if el.Type().IsObjectType() || el.Type().IsMapType() {
				valueMap := el.AsValueMap()
				stringToTest = valueMap["key"]
			}
			if el.Type().HasDynamicTypes() {
				return slices.Contains(a.extractListValues(), stringToLookFor)
			}
			if ignoreCase {
				return strings.EqualFold(stringToTest.AsString(), stringToLookFor)
			}
			if stringToTest.AsString() == stringToLookFor {
				return true
			}
		}

		return false
	})
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

func (a *Attribute) mapContains(checkValue any) bool {
	return safeOp(a, func(v cty.Value) bool {
		if !v.Type().IsObjectType() && !v.Type().IsMapType() {
			return false
		}
		valueMap := v.AsValueMap()
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
	})
}

func (a *Attribute) Contains(checkValue any, equalityOptions ...EqualityOption) bool {
	return safeOp(a, func(v cty.Value) bool {
		ignoreCase := slices.Contains(equalityOptions, IgnoreCase)

		if a.IsMapOrObject() {
			return a.mapContains(checkValue)
		}

		stringToLookFor := fmt.Sprintf("%v", checkValue)

		if v.Type().IsListType() || v.Type().IsTupleType() {
			return a.listContains(stringToLookFor, ignoreCase)
		}

		if ignoreCase {
			return containsIgnoreCase(v.AsString(), stringToLookFor)
		}

		return strings.Contains(v.AsString(), stringToLookFor)
	})
}

func containsIgnoreCase(left, substring string) bool {
	return strings.Contains(strings.ToLower(left), strings.ToLower(substring))
}

type EqualityOption int

const (
	IgnoreCase EqualityOption = iota
)

func (a *Attribute) Equals(checkValue any, equalityOptions ...EqualityOption) bool {
	return safeOp(a, func(v cty.Value) bool {
		switch v.Type() {
		case cty.String:
			if slices.Contains(equalityOptions, IgnoreCase) {
				return strings.EqualFold(strings.ToLower(v.AsString()), strings.ToLower(fmt.Sprintf("%v", checkValue)))
			}
			return strings.EqualFold(v.AsString(), fmt.Sprintf("%v", checkValue))
		case cty.Number:
			checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
			if err != nil {
				return false
			}
			return a.Value().RawEquals(checkNumber)
		case cty.Bool:
			return v.True() == checkValue
		default:
			return false
		}
	})
}

func (a *Attribute) IsTrue() bool {
	return safeOp(a, func(v cty.Value) bool {
		switch v.Type() {
		case cty.Bool:
			return v.True()
		case cty.String:
			val := v.AsString()
			val = strings.Trim(val, "\"")
			return strings.EqualFold(val, "true")
		case cty.Number:
			bf := v.AsBigFloat()
			f, _ := bf.Float64()
			return f > 0
		default:
			return false
		}
	})
}

func (a *Attribute) IsFalse() bool {
	return safeOp(a, func(v cty.Value) bool {
		switch v.Type() {
		case cty.Bool:
			return v.False()
		case cty.String:
			val := v.AsString()
			val = strings.Trim(val, "\"")
			return strings.EqualFold(val, "false")
		case cty.Number:
			bf := v.AsBigFloat()
			f, _ := bf.Float64()
			return f == 0
		default:
			return false
		}
	})
}

func (a *Attribute) IsEmpty() bool {
	if a == nil {
		return false
	}
	val := a.Value()
	ty := val.Type()
	if ty.IsTupleType() || ty.IsObjectType() {
		return val.LengthInt() == 0
	}

	if val.IsNull() {
		return a.isNullAttributeEmpty()
	}

	if !val.IsKnown() {
		return false
	}

	switch {
	case ty == cty.String:
		return val.AsString() == ""
	case ty == cty.Number:
		// a number can't ever be empty
		return false
	case ty.IsListType(), ty.IsSetType(), ty.IsMapType():
		return val.LengthInt() == 0
	}

	return true
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
	return safeOp(a, func(v cty.Value) cty.Value {
		if !v.Type().IsObjectType() && !v.Type().IsMapType() {
			return cty.NilVal
		}
		m := v.AsValueMap()
		if m == nil {
			return cty.NilVal
		}
		return m[mapKey]
	})
}

func (a *Attribute) AsMapValue() iacTypes.MapValue {
	return safeOp(a, func(v cty.Value) iacTypes.MapValue {
		if !a.IsMapOrObject() {
			return iacTypes.MapValue{}
		}

		values := make(map[string]string)
		v.ForEachElement(func(key cty.Value, val cty.Value) (stop bool) {
			if key.Type() == cty.String && key.IsKnown() &&
				val.Type() == cty.String && val.IsKnown() {
				values[key.AsString()] = val.AsString()
			}
			return false
		})
		return iacTypes.Map(values, a.GetMetadata())
	})
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

func (a *Attribute) AllReferences() []*Reference {
	if a == nil {
		return nil
	}
	return a.referencesFromExpression(a.hclAttribute.Expr)
}

func (a *Attribute) referencesFromExpression(expr hcl.Expression) []*Reference {
	if reflect.TypeOf(expr).String() == "*json.expression" {
		if ref, err := createDotReferenceFromTraversal(a.module, expr.Variables()...); err == nil {
			return []*Reference{ref}
		}
		return nil
	}

	vars := expr.Variables()
	refs := make([]*Reference, 0, len(vars))
	for _, v := range vars {
		ref, err := createDotReferenceFromTraversal(a.module, v)
		if err != nil {
			continue
		}

		if relExpr, ok := expr.(*hclsyntax.RelativeTraversalExpr); ok {
			if idxExpr, ok := relExpr.Source.(*hclsyntax.IndexExpr); ok {
				key, _ := idxExpr.Key.Value(a.ctx.Inner())
				ref.SetKey(key)
			}
		}
		refs = append(refs, ref)
	}
	return refs
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

	switch value.Type() {
	case cty.String:
		return value.AsString()
	case cty.Number:
		return value.AsBigFloat()
	case cty.Bool:
		return value.True()
	default:
		return value
	}
}

func (a *Attribute) IsNil() bool {
	return a == nil
}

func (a *Attribute) IsNotNil() bool {
	return !a.IsNil()
}

func (a *Attribute) AsNumber() float64 {
	return safeOp(a, func(v cty.Value) float64 {
		switch v.Type() {
		case cty.Number:
			v, _ := v.AsBigFloat().Float64()
			return v
		case cty.String:
			v, _ := strconv.ParseFloat(v.AsString(), 64)
			return v
		default:
			return 0
		}
	})
}

func safeOp[T any](a *Attribute, fn func(cty.Value) T) T {
	var res T
	if a == nil {
		return res
	}

	val := a.Value()
	if val.IsNull() || !val.IsKnown() {
		return res
	}

	unmarked, _ := val.UnmarkDeep()

	return fn(unmarked)
}

// RewriteExpr applies the given function `transform` to the expression of the attribute,
// recursively traversing and transforming it.
func (a *Attribute) RewriteExpr(transform func(hclsyntax.Expression) hclsyntax.Expression) {
	if a == nil || a.hclAttribute == nil {
		return
	}
	expr, ok := a.hclAttribute.Expr.(hclsyntax.Expression)
	if !ok {
		return
	}
	a.hclAttribute.Expr = RewriteExpr(expr, transform)
}

// nolint: gocyclo
// RewriteExpr recursively rewrites an HCL expression tree in-place,
// applying the provided transformation function `transform` to each node.
func RewriteExpr(
	expr hclsyntax.Expression,
	transform func(hclsyntax.Expression) hclsyntax.Expression,
) hclsyntax.Expression {
	if expr == nil {
		return nil
	}
	switch e := expr.(type) {
	case *hclsyntax.LiteralValueExpr:
	case *hclsyntax.TemplateExpr:
		for i, p := range e.Parts {
			e.Parts[i] = RewriteExpr(p, transform)
		}
	case *hclsyntax.TemplateWrapExpr:
		e.Wrapped = RewriteExpr(e.Wrapped, transform)
	case *hclsyntax.BinaryOpExpr:
		e.LHS = RewriteExpr(e.LHS, transform)
		e.RHS = RewriteExpr(e.RHS, transform)
	case *hclsyntax.UnaryOpExpr:
		e.Val = RewriteExpr(e.Val, transform)
	case *hclsyntax.TupleConsExpr:
		for i, elem := range e.Exprs {
			e.Exprs[i] = RewriteExpr(elem, transform)
		}
	case *hclsyntax.ParenthesesExpr:
		e.Expression = RewriteExpr(e.Expression, transform)
	case *hclsyntax.ObjectConsExpr:
		for i, item := range e.Items {
			e.Items[i].KeyExpr = RewriteExpr(item.KeyExpr, transform)
			e.Items[i].ValueExpr = RewriteExpr(item.ValueExpr, transform)
		}
	case *hclsyntax.ObjectConsKeyExpr:
		e.Wrapped = RewriteExpr(e.Wrapped, transform)
	case *hclsyntax.ScopeTraversalExpr:
	case *hclsyntax.RelativeTraversalExpr:
		e.Source = RewriteExpr(e.Source, transform)
	case *hclsyntax.ConditionalExpr:
		e.Condition = RewriteExpr(e.Condition, transform)
		e.TrueResult = RewriteExpr(e.TrueResult, transform)
		e.FalseResult = RewriteExpr(e.FalseResult, transform)
	case *hclsyntax.FunctionCallExpr:
		for i, arg := range e.Args {
			e.Args[i] = RewriteExpr(arg, transform)
		}
	case *hclsyntax.IndexExpr:
		e.Collection = RewriteExpr(e.Collection, transform)
		e.Key = RewriteExpr(e.Key, transform)
	case *hclsyntax.ForExpr:
		e.CollExpr = RewriteExpr(e.CollExpr, transform)
		e.KeyExpr = RewriteExpr(e.KeyExpr, transform)
		e.ValExpr = RewriteExpr(e.ValExpr, transform)
		e.CondExpr = RewriteExpr(e.CondExpr, transform)
	case *hclsyntax.SplatExpr:
		e.Source = RewriteExpr(e.Source, transform)
	case *hclsyntax.AnonSymbolExpr:
	default:
		log.Debug(
			"RewriteExpr encountered an unhandled expression type",
			log.Prefix(log.PrefixMisconfiguration),
			log.String("expr_type", fmt.Sprintf("%T", expr)),
		)
	}
	return transform(expr)
}

// UnknownValuePrefix is a placeholder string used to represent parts of a
// template expression that cannot be fully evaluated due to unknown values.
const UnknownValuePrefix = "__UNRESOLVED__"

// PartialTemplateExpr is a wrapper around hclsyntax.TemplateExpr that
// replaces unknown or unevaluated parts with placeholder strings during evaluation.
type PartialTemplateExpr struct {
	*hclsyntax.TemplateExpr
}

func (e *PartialTemplateExpr) Value(ctx *hcl.EvalContext) (cty.Value, hcl.Diagnostics) {
	parts := make([]hclsyntax.Expression, len(e.Parts))
	for i, part := range e.Parts {
		partVal, diags := part.Value(ctx)
		if diags.HasErrors() || partVal.IsNull() || !partVal.IsKnown() {
			parts[i] = &hclsyntax.LiteralValueExpr{
				Val:      cty.StringVal(UnknownValuePrefix),
				SrcRange: part.Range(),
			}
		} else if _, err := convert.Convert(partVal, cty.String); err != nil {
			parts[i] = &hclsyntax.LiteralValueExpr{
				Val:      cty.StringVal(UnknownValuePrefix),
				SrcRange: part.Range(),
			}
		} else {
			parts[i] = part
		}
	}
	newTemplate := &hclsyntax.TemplateExpr{
		Parts:    parts,
		SrcRange: e.SrcRange,
	}

	return newTemplate.Value(ctx)
}
