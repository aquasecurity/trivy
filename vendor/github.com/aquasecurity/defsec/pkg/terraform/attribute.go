package terraform

import (
	"fmt"
	"io/fs"
	"reflect"
	"regexp"
	"strings"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/scanners/terraform/context"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

type Attribute struct {
	hclAttribute *hcl.Attribute
	module       string
	ctx          *context.Context
	metadata     types.Metadata
}

func NewAttribute(attr *hcl.Attribute, ctx *context.Context, module string, parent types.Metadata, parentRef *Reference, moduleSource string, moduleFS fs.FS) *Attribute {
	rng := types.NewRange(
		attr.Range.Filename,
		attr.Range.Start.Line,
		attr.Range.End.Line,
		moduleSource,
		moduleFS,
	)
	metadata := types.NewMetadata(rng, extendReference(parentRef, attr.Name))
	return &Attribute{
		hclAttribute: attr,
		ctx:          ctx,
		module:       module,
		metadata:     metadata.WithParent(parent),
	}
}

func (a *Attribute) GetMetadata() types.Metadata {
	return a.metadata
}

func (a *Attribute) GetRawValue() interface{} {
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
		case typ.IsTupleType(), typ.IsListType():
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

func (a *Attribute) AsBytesValueOrDefault(defaultValue []byte, parent *Block) types.BytesValue {
	if a.IsNil() {
		return types.BytesDefault(defaultValue, parent.GetMetadata())
	}
	if a.IsNotResolvable() || !a.IsString() {
		return types.BytesUnresolvable(a.GetMetadata())
	}
	return types.BytesExplicit(
		[]byte(a.Value().AsString()),
		a.GetMetadata(),
	)
}

func (a *Attribute) AsStringValueOrDefault(defaultValue string, parent *Block) types.StringValue {
	if a.IsNil() {
		return types.StringDefault(defaultValue, parent.GetMetadata())
	}
	if a.IsNotResolvable() || !a.IsString() {
		return types.StringUnresolvable(a.GetMetadata())
	}
	return types.StringExplicit(
		a.Value().AsString(),
		a.GetMetadata(),
	)
}

func (a *Attribute) AsBoolValueOrDefault(defaultValue bool, parent *Block) types.BoolValue {
	if a.IsNil() {
		return types.BoolDefault(defaultValue, parent.GetMetadata())
	}
	if a.IsNotResolvable() || !a.IsBool() {
		return types.BoolUnresolvable(a.GetMetadata())
	}
	return types.BoolExplicit(
		a.IsTrue(),
		a.GetMetadata(),
	)
}

func (a *Attribute) AsIntValueOrDefault(defaultValue int, parent *Block) types.IntValue {
	if a.IsNil() {
		return types.IntDefault(defaultValue, parent.GetMetadata())
	}
	if a.IsNotResolvable() || !a.IsNumber() {
		return types.IntUnresolvable(a.GetMetadata())
	}
	big := a.Value().AsBigFloat()
	flt, _ := big.Float64()
	return types.IntExplicit(
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

func (a *Attribute) IsNumber() bool {
	if a == nil {
		return false
	}
	return !a.Value().IsNull() && a.Value().IsKnown() && a.Value().Type() == cty.Number
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

func (a *Attribute) Name() string {
	if a == nil {
		return ""
	}
	return a.hclAttribute.Name
}

func (a *Attribute) ValueAsStrings() []string {
	if a == nil {
		return nil
	}
	return getStrings(a.hclAttribute.Expr, a.ctx.Inner())
}

//nolint
func getStrings(expr hcl.Expression, ctx *hcl.EvalContext) []string {

	defer func() {
		if err := recover(); err != nil {
			_ = err
			// TODO: _= fmt.Errorf("go-cty bug detected - failed to derive value from expression: %w", err)
		}
	}()

	var results []string
	switch t := expr.(type) {
	case *hclsyntax.TupleConsExpr:
		for _, expr := range t.Exprs {
			results = append(results, getStrings(expr, ctx)...)
		}
	case *hclsyntax.FunctionCallExpr, *hclsyntax.ConditionalExpr:
		subVal, err := t.Value(ctx)
		if err == nil && subVal.Type() == cty.String {
			results = append(results, subVal.AsString())
		}
	case *hclsyntax.LiteralValueExpr:
		if t.Val.Type() == cty.String {
			results = append(results, t.Val.AsString())
		}
	case *hclsyntax.TemplateExpr:
		// walk the parts of the expression to ensure that it has a literal value
		for _, p := range t.Parts {
			results = append(results, getStrings(p, ctx)...)
		}
	case *hclsyntax.ScopeTraversalExpr:
		// handle the case for referencing a data
		if len(t.Variables()) > 0 {
			if t.Variables()[0].RootName() == "data" {
				results = append(results, "Data Reference")
				return results
			}
		}
		subVal, err := t.Value(ctx)
		if err == nil {
			switch subVal.Type() {
			case cty.String:
				results = append(results, subVal.AsString())
			default:
				subVal.ForEachElement(func(_, v cty.Value) bool {
					results = append(results, v.AsString())
					return false
				})
			}
		}
	}
	return results
}

func (a *Attribute) listContains(val cty.Value, stringToLookFor string, ignoreCase bool) bool {
	if a == nil {
		return false
	}
	valueSlice := val.AsValueSlice()
	for _, value := range valueSlice {
		stringToTest := value
		if value.Type().IsObjectType() || value.Type().IsMapType() {
			valueMap := value.AsValueMap()
			stringToTest = valueMap["key"]
		}
		if value.Type().HasDynamicTypes() {
			// References without a value can't logically "contain" a some string to check against.
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

func (a *Attribute) mapContains(checkValue interface{}, val cty.Value) bool {
	if a == nil {
		return false
	}
	valueMap := val.AsValueMap()
	switch t := checkValue.(type) {
	case map[interface{}]interface{}:
		for k, v := range t {
			for key, value := range valueMap {
				rawValue := getRawValue(value)
				if key == k && evaluate(v, rawValue) {
					return true
				}
			}
		}
		return false
	case map[string]interface{}:
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

func (a *Attribute) NotContains(checkValue interface{}, equalityOptions ...EqualityOption) bool {
	return !a.Contains(checkValue, equalityOptions...)
}

func (a *Attribute) Contains(checkValue interface{}, equalityOptions ...EqualityOption) bool {
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

func containsIgnoreCase(left, substring string) bool {
	return strings.Contains(strings.ToLower(left), strings.ToLower(substring))
}

func (a *Attribute) StartsWith(prefix interface{}) bool {
	if a == nil {
		return false
	}
	if a.Value().Type() == cty.String {
		return strings.HasPrefix(a.Value().AsString(), fmt.Sprintf("%v", prefix))
	}
	return false
}

func (a *Attribute) EndsWith(suffix interface{}) bool {
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

func (a *Attribute) Equals(checkValue interface{}, equalityOptions ...EqualityOption) bool {
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

func (a *Attribute) NotEqual(checkValue interface{}, equalityOptions ...EqualityOption) bool {
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

func (a *Attribute) IsNotAny(options ...interface{}) bool {
	return !a.IsAny(options...)
}

func (a *Attribute) IsAny(options ...interface{}) bool {
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

func (a *Attribute) IsNone(options ...interface{}) bool {
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
	switch a.Value().Type() {
	case cty.Bool:
		return a.Value().True()
	case cty.String:
		val := a.Value().AsString()
		val = strings.Trim(val, "\"")
		return strings.ToLower(val) == "true"
	case cty.Number:
		val := a.Value().AsBigFloat()
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
		return strings.ToLower(val) == "false"
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
		return len(a.Value().AsString()) == 0
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

func (a *Attribute) LessThan(checkValue interface{}) bool {
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

func (a *Attribute) LessThanOrEqualTo(checkValue interface{}) bool {
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

func (a *Attribute) GreaterThan(checkValue interface{}) bool {
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

func (a *Attribute) GreaterThanOrEqualTo(checkValue interface{}) bool {
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
	switch t := a.hclAttribute.Expr.(type) {
	case *hclsyntax.ScopeTraversalExpr:
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
	if !key.IsNull() {
		ref.SetKey(key)
	}
	return ref, nil
}

func (a *Attribute) ReferencesBlock(b *Block) bool {
	if a == nil {
		return false
	}
	for _, ref := range a.AllReferences() {
		metadata := b.GetMetadata()
		if ref.RefersTo(metadata.Reference()) {
			return true
		}
	}
	return false
}

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
		if ref, err := createDotReferenceFromTraversal(a.module, t.Variables()...); err == nil {
			refs = append(refs, ref)
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
	switch t := a.hclAttribute.Expr.(type) {
	case *hclsyntax.ScopeTraversalExpr:
		split := t.Traversal.SimpleSplit()
		return split.Abs.RootName() == resourceType
	}
	return false
}

func (a *Attribute) References(r types.Reference) bool {
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

func getRawValue(value cty.Value) interface{} {
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

func (a *Attribute) HasIntersect(checkValues ...interface{}) bool {
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
