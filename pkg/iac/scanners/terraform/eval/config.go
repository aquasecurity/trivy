package eval

import (
	"fmt"
	"io/fs"
	"maps"
	"math/rand/v2"
	"strings"

	"github.com/google/uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hcldec"
	"github.com/zclconf/go-cty/cty"
)

type AttrConfig struct {
	name       string
	underlying *hcl.Attribute
}

func (a *AttrConfig) References() []*Ref {
	return exprReferences(a.underlying.Expr)
}

func (a *AttrConfig) ToValue(evalCtx *hcl.EvalContext) (cty.Value, error) {
	val, diags := a.underlying.Expr.Value(evalCtx)
	if diags.HasErrors() {
		return cty.NilVal, diags
	}
	return val, nil
}

type BlockConfig struct {
	underlying *hcl.Block
	module     *ModuleConfig
	children   []*BlockConfig
	dynBlocks  []*DynBlockConfig
	attrs      map[string]*AttrConfig
}

// func (b *BlockConfig) References() []*Ref {
// 	var refs []*Ref
// 	for _, attr := range b.attrs {
// 		refs = append(refs, attr.References()...)
// 	}

// 	for _, childBlock := range b.children {
// 		if childBlock.underlying.Type == "dynamic" {
// 			panic("unexpected dynamic block")
// 		}
// 		refs = append(refs, childBlock.References()...)
// 	}
// 	return refs
// }

func (b *BlockConfig) Spec() hcldec.Spec {
	spec := hcldec.ObjectSpec{}
	for _, attr := range b.attrs {
		// Conversion to DynamicPseudoType always just passes through verbatim.
		spec[attr.name] = &hcldec.AttrSpec{Name: attr.name, Type: cty.DynamicPseudoType}
	}

	specsByType := make(map[string][]hcldec.Spec)

	for _, child := range b.children {
		blockType := child.underlying.Type
		childSpec := child.Spec()
		specsByType[blockType] = append(specsByType[blockType], childSpec)
	}

	for _, dynBlock := range b.dynBlocks {
		dynSpec := dynBlock.content.Spec()
		specsByType[dynBlock.blockType] = append(specsByType[dynBlock.blockType], dynSpec)
	}

	for blockType, childSpecs := range specsByType {
		if len(childSpecs) == 1 {
			spec[blockType] = &hcldec.BlockSpec{
				TypeName: blockType,
				Nested:   childSpecs[0],
			}
		} else {
			effectiveSpec := childSpecs[0]
			for _, childSpec := range childSpecs[1:] {
				effectiveSpec = mergeSpec(effectiveSpec, childSpec)
			}
			spec[blockType] = &hcldec.BlockTupleSpec{
				TypeName: blockType,
				Nested:   effectiveSpec,
			}
		}
	}
	return spec
}

var resourceRandomAttributes = map[string][]string{
	// If the user leaves the name blank, Terraform will automatically generate a unique name
	"aws_launch_template": {"name"},
	"random_id":           {"hex", "dec", "b64_url", "b64_std"},
	"random_password":     {"result", "bcrypt_hash"},
	"random_string":       {"result"},
	"random_bytes":        {"base64", "hex"},
	"random_uuid":         {"result"},
}

func (b *BlockConfig) ToValue(evalCtx *hcl.EvalContext) map[string]cty.Value {
	vals := b.toValue(evalCtx)

	// TODO: move into hooks ?
	if len(b.underlying.Labels) > 0 {
		typeLabel := b.underlying.Labels[0]
		presets := buildPresetValues(typeLabel)
		for name, presetValue := range presets {
			if _, exists := vals[name]; !exists {
				vals[name] = presetValue
			}
		}

		postValues := buildPostValues(typeLabel, vals, presets["id"])
		maps.Copy(vals, postValues)

	}
	return vals
}

func buildPresetValues(typeLabel string) map[string]cty.Value {
	vals := make(map[string]cty.Value)

	id := uuid.NewString()
	vals["id"] = cty.StringVal(id)

	if strings.HasPrefix(typeLabel, "aws_") {
		vals["arn"] = cty.StringVal(id)
	}

	switch typeLabel {
	// workaround for weird iam feature
	case "aws_iam_policy_document":
		vals["json"] = cty.StringVal(id)
	// allow referencing the current region name
	case "aws_region":
		vals["name"] = cty.StringVal("current-region")
	case "random_integer":
		//nolint:gosec
		vals["result"] = cty.NumberIntVal(rand.Int64())
	}

	if attrs, exists := resourceRandomAttributes[typeLabel]; exists {
		for _, attr := range attrs {
			vals[attr] = cty.StringVal(uuid.New().String())
		}
	}
	return vals
}

func buildPostValues(typeLabel string, current map[string]cty.Value, id cty.Value) map[string]cty.Value {
	vals := make(map[string]cty.Value)
	if strings.HasPrefix(typeLabel, "aws_s3_bucket") {
		if bucket, ok := current["bucket"]; ok {
			vals["id"] = bucket
		} else {
			vals["bucket"] = id
		}
	}

	if typeLabel == "aws_s3_bucket" {
		var bucketName string
		if bucket := current["bucket"]; bucket.Type() == cty.String && bucket.IsKnown() {
			bucketName = bucket.AsString()
		}
		vals["arn"] = cty.StringVal(fmt.Sprintf("arn:aws:s3:::%s", bucketName))
	}
	return vals
}

func (b *BlockConfig) toValue(evalCtx *hcl.EvalContext) map[string]cty.Value {
	vals := make(map[string]cty.Value)

	for _, attr := range b.attrs {
		if attr.name == "count" || attr.name == "for_each" {
			continue
		}
		val, err := attr.ToValue(evalCtx)
		if err != nil {
			val = cty.DynamicVal
		}
		vals[attr.name] = val
	}

	blocksByType := make(map[string][]*BlockConfig)
	for _, childBlock := range b.children {
		typ := childBlock.underlying.Type
		blocksByType[typ] = append(blocksByType[typ], childBlock)
	}

	for typ, childBlocks := range blocksByType {
		elems := make([]cty.Value, 0, len(childBlocks))
		for _, childBlock := range childBlocks {
			val := childBlock.toValue(evalCtx)
			elems = append(elems, cty.ObjectVal(val))
		}
		if len(childBlocks) == 1 {
			vals[typ] = elems[0]
		} else {
			vals[typ] = cty.TupleVal(elems)
		}
	}
	return vals
}

type DynBlockConfig struct {
	blockType    string
	forEach      *AttrConfig
	iteratorName string
	content      *BlockConfig
}

// func (d *DynBlockConfig) Expand(evalCtx *hcl.EvalContext) ([]*BlockConfig, error) {
// 	val, err := d.forEach.ToValue(evalCtx)
// 	if err != nil {
// 		return nil, err
// 	}

// 	iter, err := expandForEach(val)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var blocks []*BlockConfig

// 	for eachKey, eachVal := range iter {
// 		contentCtx := evalCtx.NewChild()
// 		contentCtx.Variables["each"] = cty.ObjectVal(map[string]cty.Value{
// 			"key":   cty.StringVal(eachKey),
// 			"value": eachVal,
// 		})
// 		expanded := d.Content.Expand(contentCtx)
// 		blocks = append(blocks, expanded...)
// 	}
// 	return blocks, nil
// }

type ModuleConfig struct {
	Name string
	FS   fs.FS
	Dir  string
	// empty for root module
	Block  *BlockConfig
	Blocks []*BlockConfig
	// empty for root module
	Parent   *ModuleConfig
	Children []*ModuleConfig

	ModuleCalls map[string]*ModuleCall

	LogicalSource string
}

func (c *ModuleConfig) Descendant(addr ModuleAddr) *ModuleConfig {
	curr := c
	for _, step := range addr {
		for _, child := range c.Children {
			if child.Name == step {
				curr = child
			}
			if curr == nil {
				return nil
			}
		}
	}

	return curr
}

type ModuleCall struct {
	Name string

	Source  string
	Version string

	Config *BlockConfig

	FS   fs.FS
	Path string
}

func (m *ModuleConfig) IsRoot() bool {
	return m.Parent == nil
}

func (m *ModuleConfig) AbsAddr() ModuleAddr {
	if m.IsRoot() {
		return ModuleAddr{}
	}

	path := ModuleAddr{m.Name}
	return append(m.Parent.AbsAddr(), path...)
}
