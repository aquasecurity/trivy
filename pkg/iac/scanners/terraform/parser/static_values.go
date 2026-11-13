package parser

import (
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	tfcontext "github.com/aquasecurity/trivy/pkg/iac/terraform/context"
	"github.com/aquasecurity/trivy/pkg/set"
)

// setStaticValues adds to ctx the variables of the module and the locals that its module calls depend on.
// Variables come from inputs or from their defaults, and locals are computed from them.
// A reference to anything else, or to a local in a reference cycle, gives an unknown value.
func setStaticValues(ctx *tfcontext.Context, blocks terraform.Blocks, inputs map[string]cty.Value) {
	vars := make(map[string]cty.Value)
	for _, b := range blocks.OfType("variable") {
		if val, err := variableValue(b, inputs); err == nil {
			vars[b.Label()] = val
		}
	}
	ctx.Set(cty.ObjectVal(vars), "var")

	locals := staticLocals{
		ctx:      ctx,
		exprs:    make(map[string]*terraform.Attribute),
		visiting: set.New[string](),
		done:     set.New[string](),
	}
	for _, b := range blocks.OfType("locals") {
		for _, attr := range b.GetAttributes() {
			locals.exprs[attr.Name()] = attr
		}
	}
	var names []string
	for _, call := range blocks.OfType("module") {
		for _, attr := range call.GetAttributes() {
			names = append(names, localRefs(attr.HCLAttribute().Expr)...)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		locals.evaluate(name)
	}
}

// staticLocals holds the expressions of the module locals and the context that receives their values.
type staticLocals struct {
	ctx      *tfcontext.Context
	exprs    map[string]*terraform.Attribute
	visiting set.Set[string]
	done     set.Set[string]
}

// evaluate computes the locals that the local references, then the local itself,
// and adds them to the context.
func (s *staticLocals) evaluate(name string) {
	attr, exists := s.exprs[name]
	if !exists || s.done.Contains(name) || s.visiting.Contains(name) {
		return
	}

	s.visiting.Append(name)
	for _, ref := range localRefs(attr.HCLAttribute().Expr) {
		s.evaluate(ref)
	}

	val := attr.Value()
	if val == cty.NilVal {
		val = cty.DynamicVal
	}
	s.ctx.Set(val, "local", name)
	s.done.Append(name)
}

// localRefs returns the names of the locals that expr references.
func localRefs(expr hcl.Expression) []string {
	var names []string
	for _, traversal := range expr.Variables() {
		if traversal.RootName() != "local" || len(traversal) < 2 {
			continue
		}
		if attr, ok := traversal[1].(hcl.TraverseAttr); ok {
			names = append(names, attr.Name)
		}
	}
	return names
}
