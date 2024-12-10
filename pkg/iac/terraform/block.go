package terraform

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"

	"github.com/aquasecurity/trivy/pkg/iac/terraform/context"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Block struct {
	id           string
	hclBlock     *hcl.Block
	context      *context.Context
	moduleBlock  *Block
	parentBlock  *Block
	expanded     bool
	cloneIndex   int
	childBlocks  []*Block
	attributes   []*Attribute
	metadata     iacTypes.Metadata
	moduleSource string
	moduleFS     fs.FS
	reference    Reference
}

func NewBlock(hclBlock *hcl.Block, ctx *context.Context, moduleBlock *Block, parentBlock *Block, moduleSource string,
	moduleFS fs.FS, index ...cty.Value) *Block {
	if ctx == nil {
		ctx = context.NewContext(&hcl.EvalContext{}, nil)
	}

	var r hcl.Range
	switch body := hclBlock.Body.(type) {
	case *hclsyntax.Body:
		r = body.SrcRange
	default:
		r = hclBlock.DefRange
		r.End = hclBlock.Body.MissingItemRange().End
	}
	moduleName := "root"
	if moduleBlock != nil {
		moduleName = moduleBlock.FullName()
	}
	rng := iacTypes.NewRange(
		r.Filename,
		r.Start.Line,
		r.End.Line,
		moduleSource,
		moduleFS,
	)

	var parts []string
	// if there are no labels then use the block type
	// this is for the case where "special" keywords like "resource" are used
	// as normal block names in top level blocks - see issue tfsec#1528 for an example
	if hclBlock.Type != "resource" || len(hclBlock.Labels) == 0 {
		parts = append(parts, hclBlock.Type)
	}
	parts = append(parts, hclBlock.Labels...)

	var parent string
	if moduleBlock != nil {
		parent = moduleBlock.FullName()
	}
	ref, _ := newReference(parts, parent)
	if len(index) > 0 {
		key := index[0]
		ref.SetKey(key)
	}

	metadata := iacTypes.NewMetadata(rng, ref.String())

	if parentBlock != nil {
		metadata = metadata.WithParent(parentBlock.metadata)
	} else if moduleBlock != nil {
		metadata = metadata.WithParent(moduleBlock.GetMetadata())
	}

	b := Block{
		id:           uuid.NewString(),
		context:      ctx,
		hclBlock:     hclBlock,
		moduleBlock:  moduleBlock,
		moduleSource: moduleSource,
		moduleFS:     moduleFS,
		parentBlock:  parentBlock,
		metadata:     metadata,
		reference:    *ref,
	}

	var children Blocks
	switch body := hclBlock.Body.(type) {
	case *hclsyntax.Body:
		for _, b2 := range body.Blocks {
			children = append(children, NewBlock(b2.AsHCLBlock(), ctx, moduleBlock, &b, moduleSource, moduleFS))
		}
	default:
		content, _, diag := hclBlock.Body.PartialContent(Schema)
		if diag == nil {
			for _, hb := range content.Blocks {
				children = append(children, NewBlock(hb, ctx, moduleBlock, &b, moduleSource, moduleFS))
			}
		}
	}

	b.childBlocks = children

	for _, attr := range b.createAttributes() {
		b.attributes = append(b.attributes, NewAttribute(attr, ctx, moduleName, metadata, *ref, moduleSource, moduleFS))
	}

	return &b
}

func (b *Block) ID() string {
	return b.id
}

func (b *Block) Reference() Reference {
	return b.reference
}

func (b *Block) GetMetadata() iacTypes.Metadata {
	return b.metadata
}

func (b *Block) GetRawValue() any {
	return nil
}

func (b *Block) injectBlock(block *Block) {
	for attrName, attr := range block.Attributes() {
		path := fmt.Sprintf("%s.%s.%s", b.reference.String(), block.hclBlock.Type, attrName)
		b.context.Root().SetByDot(attr.Value(), path)
	}
	b.childBlocks = append(b.childBlocks, block)
}

func (b *Block) markExpanded() {
	b.expanded = true
}

func (b *Block) IsExpanded() bool {
	return b.expanded
}

func (b *Block) inherit(ctx *context.Context, index ...cty.Value) *Block {
	return NewBlock(b.copyBlock(), ctx, b.moduleBlock, b.parentBlock, b.moduleSource, b.moduleFS, index...)
}

func (b *Block) copyBlock() *hcl.Block {
	hclBlock := *b.hclBlock
	return &hclBlock
}

func (b *Block) childContext() *context.Context {
	if b.context == nil {
		return context.NewContext(&hcl.EvalContext{}, nil)
	}
	return b.context.NewChild()
}

func (b *Block) Clone(index cty.Value) *Block {
	childCtx := b.childContext()
	clone := b.inherit(childCtx, index)

	if len(clone.hclBlock.Labels) > 0 {
		position := len(clone.hclBlock.Labels) - 1
		labels := make([]string, len(clone.hclBlock.Labels))
		for i := 0; i < len(labels); i++ {
			labels[i] = clone.hclBlock.Labels[i]
		}
		if index.IsKnown() && !index.IsNull() {
			switch index.Type() {
			case cty.Number:
				f, _ := index.AsBigFloat().Float64()
				labels[position] = fmt.Sprintf("%s[%d]", clone.hclBlock.Labels[position], int(f))
			case cty.String:
				labels[position] = fmt.Sprintf("%s[%q]", clone.hclBlock.Labels[position], index.AsString())
			default:
				labels[position] = fmt.Sprintf("%s[%#v]", clone.hclBlock.Labels[position], index)
			}
		} else {
			labels[position] = fmt.Sprintf("%s[%d]", clone.hclBlock.Labels[position], b.cloneIndex)
		}
		clone.hclBlock.Labels = labels
	}
	indexVal, _ := gocty.ToCtyValue(index, cty.Number)
	clone.context.SetByDot(indexVal, "count.index")
	clone.markExpanded()
	b.cloneIndex++
	return clone
}

func (b *Block) Context() *context.Context {
	return b.context
}

func (b *Block) OverrideContext(ctx *context.Context) {
	b.context = ctx
	for _, block := range b.childBlocks {
		block.OverrideContext(ctx.NewChild())
	}
	for _, attr := range b.attributes {
		attr.ctx = ctx
	}
}

func (b *Block) Type() string {
	return b.hclBlock.Type
}

func (b *Block) Labels() []string {
	return b.hclBlock.Labels
}

func (b *Block) GetFirstMatchingBlock(names ...string) *Block {
	var returnBlock *Block
	for _, name := range names {
		childBlock := b.GetBlock(name)
		if childBlock.IsNotNil() {
			return childBlock
		}
	}
	return returnBlock
}

func (b *Block) createAttributes() hcl.Attributes {
	switch body := b.hclBlock.Body.(type) {
	case *hclsyntax.Body:
		attributes := make(hcl.Attributes)
		for _, a := range body.Attributes {
			attributes[a.Name] = a.AsHCLAttribute()
		}
		return attributes
	default:
		_, body, diag := b.hclBlock.Body.PartialContent(Schema)
		if diag != nil {
			return nil
		}
		attrs, diag := body.JustAttributes()
		if diag != nil {
			return nil
		}
		return attrs
	}
}

func (b *Block) GetBlock(name string) *Block {
	var returnBlock *Block
	if b == nil || b.hclBlock == nil {
		return returnBlock
	}
	for _, child := range b.childBlocks {
		if child.Type() == name {
			return child
		}
	}
	return returnBlock
}

func (b *Block) AllBlocks() Blocks {
	if b == nil || b.hclBlock == nil {
		return nil
	}
	return b.childBlocks
}

func (b *Block) GetBlocks(name string) Blocks {
	if b == nil || b.hclBlock == nil {
		return nil
	}
	var results []*Block
	for _, child := range b.childBlocks {
		if child.Type() == name {
			results = append(results, child)
		}
	}
	return results
}

func (b *Block) GetAttributes() []*Attribute {
	if b == nil {
		return nil
	}
	return b.attributes
}

func (b *Block) GetAttribute(name string) *Attribute {
	if b == nil || b.hclBlock == nil {
		return nil
	}
	for _, attr := range b.attributes {
		if attr.Name() == name {
			return attr
		}
	}
	return nil
}

// GetValueByPath returns the value of the attribute located at the given path.
// Supports special paths like "count.index," "each.key," and "each.value."
// The path may contain indices, keys and dots (used as separators).
func (b *Block) GetValueByPath(path string) cty.Value {

	if path == "count.index" || path == "each.key" || path == "each.value" {
		return b.Context().GetByDot(path)
	}

	if restPath, ok := strings.CutPrefix(path, "each.value."); ok {
		if restPath == "" {
			return cty.NilVal
		}

		val := b.Context().GetByDot("each.value")
		res, err := getValueByPath(val, strings.Split(restPath, "."))
		if err != nil {
			return cty.NilVal
		}
		return res
	}

	attr, restPath := b.getAttributeByPath(path)

	if attr == nil {
		return cty.NilVal
	}

	if !attr.IsIterable() || len(restPath) == 0 {
		return attr.Value()
	}

	res, err := getValueByPath(attr.Value(), restPath)
	if err != nil {
		return cty.NilVal
	}
	return res
}

func (b *Block) getAttributeByPath(path string) (*Attribute, []string) {
	steps := strings.Split(path, ".")

	if len(steps) == 1 {
		return b.GetAttribute(steps[0]), nil
	}

	var (
		attribute *Attribute
		stepIndex int
	)

	for currentBlock := b; currentBlock != nil && stepIndex < len(steps); {
		blocks := currentBlock.GetBlocks(steps[stepIndex])
		var nextBlock *Block
		if !hasIndex(steps, stepIndex+1) && len(blocks) > 0 {
			// if index is not provided then return the first block for backwards compatibility
			nextBlock = blocks[0]
		} else if len(blocks) > 1 && stepIndex < len(steps)-2 {
			// handling the case when there are multiple blocks with the same name,
			// e.g. when using a `dynamic` block
			indexVal, err := strconv.Atoi(steps[stepIndex+1])
			if err == nil && indexVal >= 0 && indexVal < len(blocks) {
				nextBlock = blocks[indexVal]
				stepIndex++
			}
		}

		if nextBlock == nil {
			attribute = currentBlock.GetAttribute(steps[stepIndex])
		}

		currentBlock = nextBlock
		stepIndex++
	}

	return attribute, steps[stepIndex:]
}

func hasIndex(steps []string, idx int) bool {
	if idx < 0 || idx >= len(steps) {
		return false
	}
	_, err := strconv.Atoi(steps[idx])
	return err == nil
}

func getValueByPath(val cty.Value, path []string) (cty.Value, error) {
	var err error
	for _, step := range path {
		switch valType := val.Type(); {
		case valType.IsMapType():
			val, err = cty.IndexStringPath(step).Apply(val)
		case valType.IsObjectType():
			val, err = cty.GetAttrPath(step).Apply(val)
		case valType.IsListType() || valType.IsTupleType():
			var idx int
			idx, err = strconv.Atoi(step)
			if err != nil {
				return cty.NilVal, fmt.Errorf("index %q is not a number", step)
			}
			val, err = cty.IndexIntPath(idx).Apply(val)
		default:
			return cty.NilVal, fmt.Errorf(
				"unexpected value type %s for path step %q",
				valType.FriendlyName(), step,
			)
		}
		if err != nil {
			return cty.NilVal, err
		}
	}
	return val, nil
}

func (b *Block) GetNestedAttribute(name string) (*Attribute, *Block) {

	parts := strings.Split(name, ".")
	blocks := parts[:len(parts)-1]
	attrName := parts[len(parts)-1]

	working := b
	for _, subBlock := range blocks {
		if checkBlock := working.GetBlock(subBlock); checkBlock == nil {
			return nil, working
		} else {
			working = checkBlock
		}
	}

	if working != nil {
		if attr := working.GetAttribute(attrName); attr != nil {
			return attr, working
		}
	}

	return nil, b
}

func MapNestedAttribute[T any](block *Block, path string, f func(attr *Attribute, parent *Block) T) T {
	return f(block.GetNestedAttribute(path))
}

// LocalName is the name relative to the current module
func (b *Block) LocalName() string {
	return b.reference.String()
}

func (b *Block) FullLocalName() string {
	if b.parentBlock != nil {
		return fmt.Sprintf(
			"%s.%s",
			b.parentBlock.FullLocalName(),
			b.LocalName(),
		)
	}
	return b.LocalName()
}

func (b *Block) FullName() string {

	if b.moduleBlock != nil {
		return fmt.Sprintf(
			"%s.%s",
			b.moduleBlock.FullName(),
			b.LocalName(),
		)
	}

	return b.LocalName()
}

func (b *Block) ModuleKey() string {
	name := b.Reference().NameLabel()
	if b.moduleBlock == nil {
		return name
	}
	return fmt.Sprintf("%s.%s", b.moduleBlock.ModuleKey(), name)
}

func (b *Block) UniqueName() string {
	if b.moduleBlock != nil {
		return fmt.Sprintf("%s:%s:%s", b.FullName(), b.metadata.Range().GetFilename(), b.moduleBlock.UniqueName())
	}
	return fmt.Sprintf("%s:%s", b.FullName(), b.metadata.Range().GetFilename())
}

func (b *Block) TypeLabel() string {
	if len(b.Labels()) > 0 {
		return b.Labels()[0]
	}
	return ""
}

func (b *Block) NameLabel() string {
	if len(b.Labels()) > 1 {
		return b.Labels()[1]
	}
	return ""
}

func (b *Block) HasChild(childElement string) bool {
	return b.GetAttribute(childElement).IsNotNil() || b.GetBlock(childElement).IsNotNil()
}

func (b *Block) MissingChild(childElement string) bool {
	if b == nil {
		return true
	}

	return !b.HasChild(childElement)
}

func (b *Block) MissingNestedChild(name string) bool {
	if b == nil {
		return true
	}

	parts := strings.Split(name, ".")
	blocks := parts[:len(parts)-1]
	last := parts[len(parts)-1]

	working := b
	for _, subBlock := range blocks {
		if checkBlock := working.GetBlock(subBlock); checkBlock == nil {
			return true
		} else {
			working = checkBlock
		}
	}
	return !working.HasChild(last)

}

func (b *Block) InModule() bool {
	if b == nil {
		return false
	}
	return b.moduleBlock != nil
}

func (b *Block) Label() string {
	return strings.Join(b.hclBlock.Labels, ".")
}

func (b *Block) IsResourceType(resourceType string) bool {
	return b.TypeLabel() == resourceType
}

func (b *Block) IsEmpty() bool {
	return len(b.AllBlocks()) == 0 && len(b.GetAttributes()) == 0
}

func (b *Block) Attributes() map[string]*Attribute {
	attributes := make(map[string]*Attribute)
	for _, attr := range b.GetAttributes() {
		attributes[attr.Name()] = attr
	}
	return attributes
}

func (b *Block) Values() cty.Value {
	values := createPresetValues(b)
	for _, attribute := range b.GetAttributes() {
		if attribute.Name() == "for_each" {
			continue
		}
		values[attribute.Name()] = attribute.NullableValue()
	}
	return cty.ObjectVal(postProcessValues(b, values))
}

func (b *Block) IsNil() bool {
	return b == nil
}

func (b *Block) IsNotNil() bool {
	return !b.IsNil()
}

func (b *Block) ExpandBlock() error {
	var (
		expanded []*Block
		errs     error
	)

	for _, child := range b.childBlocks {
		if child.Type() == "dynamic" {
			blocks, err := child.expandDynamic()
			if err != nil {
				errs = multierror.Append(errs, err)
				continue
			}
			expanded = append(expanded, blocks...)
		}
	}

	for _, block := range expanded {
		b.injectBlock(block)
	}

	return errs
}

func (b *Block) expandDynamic() ([]*Block, error) {
	if b.IsExpanded() || b.Type() != "dynamic" {
		return nil, nil
	}

	realBlockType := b.TypeLabel()
	if realBlockType == "" {
		return nil, errors.New("dynamic block must have 1 label")
	}

	forEachVal, err := b.validateForEach()
	if err != nil {
		return nil, fmt.Errorf("invalid for-each in %s block: %w", b.FullLocalName(), err)
	}

	var (
		expanded []*Block
		errs     error
	)

	forEachVal.ForEachElement(func(key, val cty.Value) (stop bool) {
		if val.IsNull() || !val.IsKnown() {
			return
		}

		iteratorName, err := b.iteratorName(realBlockType)
		if err != nil {
			errs = multierror.Append(errs, err)
			return
		}

		forEachCtx := b.childContext()
		obj := cty.ObjectVal(map[string]cty.Value{
			"key":   key,
			"value": val,
		})
		forEachCtx.Set(obj, iteratorName)

		if content := b.GetBlock("content"); content != nil {
			inherited := content.inherit(forEachCtx)
			inherited.hclBlock.Labels = []string{}
			inherited.hclBlock.Type = realBlockType
			if err := inherited.ExpandBlock(); err != nil {
				errs = multierror.Append(errs, err)
				return
			}
			expanded = append(expanded, inherited)
		}
		return
	})

	if len(expanded) > 0 {
		b.markExpanded()
	}

	return expanded, errs
}

func (b *Block) validateForEach() (cty.Value, error) {
	forEachAttr := b.GetAttribute("for_each")
	if forEachAttr == nil {
		return cty.NilVal, errors.New("for_each attribute required")
	}

	forEachVal := forEachAttr.Value()

	if !forEachVal.CanIterateElements() {
		return cty.NilVal, fmt.Errorf("cannot use a %s value in for_each. An iterable collection is required", forEachVal.GoString())
	}

	return forEachVal, nil
}

func (b *Block) iteratorName(blockType string) (string, error) {
	iteratorAttr := b.GetAttribute("iterator")
	if iteratorAttr == nil {
		return blockType, nil
	}

	traversal, diags := hcl.AbsTraversalForExpr(iteratorAttr.hclAttribute.Expr)
	if diags.HasErrors() {
		return "", diags
	}

	if len(traversal) != 1 {
		return "", errors.New("dynamic iterator must be a single variable name")
	}

	return traversal.RootName(), nil
}
