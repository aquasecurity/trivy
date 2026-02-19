package eval

import (
	"io/fs"
	"reflect"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/customdecode"
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
	attrs      map[string]*AttrConfig
	children   []*BlockConfig

	dynBlocks []*DynBlockConfig

	specCache hcldec.Spec
}

// dynamicType is a special cty capsule type named "dynamic".
// It is used to attach a custom decoder for HCL expressions when decoding blocks into cty.Value.
// The custom decoder ensures that if the expression evaluates to null or returns errors,
// the value is replaced with cty.DynamicVal instead of propagating a null or failing.
//
// This allows handling dynamic or unknown values safely during evaluation.
var dynamicType = cty.CapsuleWithOps("dynamic", reflect.TypeFor[cty.Type](), &cty.CapsuleOps{
	ExtensionData: func(key any) any {
		switch key {
		case customdecode.CustomExpressionDecoder:
			return customdecode.CustomExpressionDecoderFunc(func(expr hcl.Expression, ctx *hcl.EvalContext) (cty.Value, hcl.Diagnostics) {
				val, diags := expr.Value(ctx)
				if val.IsNull() || diags.HasErrors() {
					return cty.DynamicVal, nil
				}
				return val, nil
			})
		default:
			return nil
		}
	},
})

// Spec returns the HCL specification of this block configuration.
//
// The specification is necessary for processing the HCL body using functions
// from the hcl package, for example to extract used variables or decode
// the block into cty.Value.
//
// In Terraform, specifications are usually provided by providers. In this
// static analysis context, we treat the current configuration as authoritative
// and use it to reconstruct the block specification.
func (b *BlockConfig) Spec() hcldec.Spec {
	if b.specCache != nil {
		return b.specCache
	}

	spec := hcldec.ObjectSpec{}
	for _, attr := range b.attrs {
		// Conversion to DynamicPseudoType always just passes through verbatim.
		// spec[attr.name] = &hcldec.AttrSpec{Name: attr.name, Type: cty.DynamicPseudoType}
		spec[attr.name] = &hcldec.AttrSpec{Name: attr.name, Type: dynamicType}
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

	b.specCache = spec
	return spec
}

type DynBlockConfig struct {
	blockType    string
	forEach      *AttrConfig
	iteratorName string
	content      *BlockConfig
}

// SourceChain represents the chain of module sources from the root to this module.
// Each source can be a remote path, Git URL, or registry reference.
// Local paths (starting with "." or "..") are not included in the chain,
// since their provenance is determined by the filesystem.
//
// Example:
//
//	root := SourceChain("github.com/org/root-module")
//	child := root.Extend("github.com/org/submodule")
//	fmt.Println(child) // github.com/org/root-module/github.com/org/submodule
type SourceChain string

// NewSourceChain returns a SourceChain for the given module source.
// For remote or registry sources, it creates a chain by extending the parentChain.
// For local paths (starting with "." or ".."), it returns an empty chain because
// local modules are identified by filesystem paths.
func NewSourceChain(source string) SourceChain {
	if strings.HasPrefix(source, ".") || strings.HasPrefix(source, "..") {
		return "" // local modules: chain not needed
	}
	return SourceChain(source)
}

// Extend returns a new SourceChain with the given source appended.
// If the chain is empty, it returns a chain containing only the new source.
func (s SourceChain) Extend(source string) SourceChain {
	if s == "" {
		return SourceChain(source)
	}
	return SourceChain(string(s) + "/" + source)
}

type ModuleConfig struct {
	Name        string
	FS          fs.FS
	Path        string
	SourceChain SourceChain

	// empty for root module
	Config *BlockConfig
	Blocks []*BlockConfig
	// empty for root module
	Parent      *ModuleConfig
	Children    []*ModuleConfig
	ModuleCalls map[string]*ModuleCall

	Unresolvable bool
}

func (c *ModuleConfig) Descendant(addr ModuleAddr) *ModuleConfig {
	curr := c
	for _, step := range addr {
		var next *ModuleConfig
		for _, child := range curr.Children {
			if child.Name == step {
				next = child
				break
			}
		}
		if next == nil {
			return nil
		}
		curr = next
	}
	return curr
}

type ModuleCall struct {
	Name string
	FS   fs.FS
	Path string

	Source  string
	Version string

	Config *BlockConfig
}

func (m *ModuleConfig) IsRoot() bool {
	return m.Parent == nil
}

func (m *ModuleConfig) AbsAddr() ModuleAddr {
	if m.IsRoot() {
		return RootModule
	}
	parent := m.Parent.AbsAddr()
	return append(slices.Clone(parent), m.Name)
}
