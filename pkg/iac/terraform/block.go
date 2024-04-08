package terraform

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/google/uuid"
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
		id:           uuid.New().String(),
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

func (b *Block) GetRawValue() interface{} {
	return nil
}

func (b *Block) InjectBlock(block *Block, name string) {
	block.hclBlock.Labels = []string{}
	block.hclBlock.Type = name
	for attrName, attr := range block.Attributes() {
		b.context.Root().SetByDot(attr.Value(), fmt.Sprintf("%s.%s.%s", b.reference.String(), name, attrName))
	}
	b.childBlocks = append(b.childBlocks, block)
}

func (b *Block) MarkExpanded() {
	b.expanded = true
}

func (b *Block) IsExpanded() bool {
	return b.expanded
}

func (b *Block) Clone(index cty.Value) *Block {
	var childCtx *context.Context
	if b.context != nil {
		childCtx = b.context.NewChild()
	} else {
		childCtx = context.NewContext(&hcl.EvalContext{}, nil)
	}

	cloneHCL := *b.hclBlock

	clone := NewBlock(&cloneHCL, childCtx, b.moduleBlock, b.parentBlock, b.moduleSource, b.moduleFS, index)
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
	clone.MarkExpanded()
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

func (b *Block) ModuleName() string {
	name := strings.TrimPrefix(b.LocalName(), "module.")
	if b.moduleBlock != nil {
		module := strings.TrimPrefix(b.moduleBlock.FullName(), "module.")
		name = fmt.Sprintf(
			"%s.%s",
			module,
			name,
		)
	}
	var parts []string
	for _, part := range strings.Split(name, ".") {
		part = strings.Split(part, "[")[0]
		parts = append(parts, part)
	}
	return strings.Join(parts, ".")
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
		values[attribute.Name()] = attribute.Value()
	}
	return cty.ObjectVal(postProcessValues(b, values))
}

func (b *Block) IsNil() bool {
	return b == nil
}

func (b *Block) IsNotNil() bool {
	return !b.IsNil()
}
