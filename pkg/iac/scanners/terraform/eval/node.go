package eval

import (
	"fmt"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/dynblock"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

type Referencer interface {
	References() []*Ref
}

type Executable interface {
	Execute(state *EvalState) error
}

type Node interface {
	ID() string
	Module() ModuleAddr
}

type BaseNode struct {
	id         string
	moduleAddr ModuleAddr
}

func newBaseNode(addr Address, moduleAddr ModuleAddr) *BaseNode {
	return &BaseNode{
		id:         addr.Key(),
		moduleAddr: moduleAddr,
	}
}

func (n *BaseNode) ID() string {
	return n.id
}

func (n *BaseNode) Module() ModuleAddr {
	return n.moduleAddr
}

var _ Referencer = (*AttributeReferencer)(nil)

type AttributeReferencer struct {
	Attr *AttrConfig
}

func (n *AttributeReferencer) References() []*Ref {
	if n.Attr == nil {
		return nil
	}
	return exprReferences(n.Attr.underlying.Expr)
}

type NodeRoot struct {
	module ModuleAddr
}

func (n *NodeRoot) ID() string {
	return "<root>"
}

func (n *NodeRoot) Module() ModuleAddr {
	return n.module
}

var _ Executable = (*NodeRootVariable)(nil)

type NodeRootVariable struct {
	*BaseNode
	Name    string
	Default *AttrConfig
	Type    *AttrConfig
}

func (n *NodeRootVariable) Execute(state *EvalState) error {
	return state.forEachModule(n.Module(), func(mi *ModuleInstance) error {
		val := cty.DynamicVal
		var evalErr error

		if v, exists := state.opts.InputVars[n.Name]; exists && !v.Type().Equals(cty.NilType) {
			val = v
		} else if n.Default != nil {
			v, err := n.Default.ToValue(&hcl.EvalContext{})
			if err != nil {
				val = cty.DynamicVal
			} else {
				val = v
			}
		} else {
			evalErr = fmt.Errorf(
				"input variable at %q is required but was not provided and has no default value",
				mi.scope.addr.Key(),
			)
		}

		val, err := applyTypeAndDefaults(
			val,
			n.Type,
			mi.scope.addr.Key(),
		)
		if err != nil {
			evalErr = multierror.Append(evalErr, err)
		}

		mi.scope.vars[n.Name] = val
		return evalErr
	})
}

var _ Referencer = (*NodeVariable)(nil)
var _ Executable = (*NodeVariable)(nil)

type NodeVariable struct {
	*BaseNode
	*AttributeReferencer
	Name    string
	Default *AttrConfig
	Type    *AttrConfig
}

func (n *NodeVariable) Execute(state *EvalState) error {
	return state.forEachModule(n.Module(), func(mi *ModuleInstance) error {
		val := cty.DynamicVal
		var evalErr error

		if n.Attr != nil {
			if moduleData, err := mi.instanceData(); err != nil {
				evalErr = fmt.Errorf("get module instance data for variable at %s: %w",
					mi.scope.addr.Key(), err)
			} else if v, err := state.evalExpr(mi.parent.scope, n.Attr.underlying.Expr, moduleData); err != nil {
				evalErr = fmt.Errorf("evaluate expression of variable at %s: %w",
					mi.scope.addr.Key(), err)
			} else {
				val = v
			}
		}

		if val == cty.DynamicVal && n.Default != nil {
			v, err := n.Default.ToValue(&hcl.EvalContext{})
			if err != nil {
				evalErr = multierror.Append(evalErr, err)
			} else {
				val = v
			}
		}

		val, err := applyTypeAndDefaults(val, n.Type, mi.scope.addr.Key())
		if err != nil {
			evalErr = multierror.Append(evalErr, err)
		}

		mi.scope.vars[n.Name] = val
		return evalErr
	})
}

func applyTypeAndDefaults(
	val cty.Value,
	typeAttr *AttrConfig,
	ctx string,
) (cty.Value, error) {
	if typeAttr == nil {
		return val, nil
	}

	valType, defaults, err := decodeVarType(typeAttr.underlying.Expr)
	if err != nil {
		return cty.NilVal, fmt.Errorf(
			"failed to decode variable type at %s: %w",
			ctx,
			err,
		)
	}

	if defaults != nil {
		val = defaults.Apply(val)
	}

	typedVal, err := convert.Convert(val, valType)
	if err != nil {
		return cty.NilVal, fmt.Errorf(
			"failed to convert value %s to %s at %s: %w",
			val.GoString(),
			valType.FriendlyName(),
			ctx,
			err,
		)
	}

	return typedVal, nil
}

var _ Referencer = (*NodeLocal)(nil)
var _ Executable = (*NodeLocal)(nil)

type NodeLocal struct {
	*BaseNode
	*AttributeReferencer
	Name string
}

func (n *NodeLocal) Execute(state *EvalState) error {
	return state.forEachModule(n.Module(), func(mi *ModuleInstance) error {
		val, err := state.evalExpr(mi.scope, n.Attr.underlying.Expr, NoInstanceData)
		if err != nil {
			return fmt.Errorf("eval %s: %w", n.Name, err)
		}
		mi.scope.locals[n.Name] = val
		return nil
	})
}

var _ Referencer = (*NodeProvider)(nil)
var _ Executable = (*NodeProvider)(nil)

type NodeProvider struct {
	*BaseNode
	Name   string
	Config *BlockConfig
}

func (n *NodeProvider) References() []*Ref {
	traversals := dynblock.VariablesHCLDec(n.Config.underlying.Body, n.Config.Spec())
	return travReferences(traversals)
}

func (n *NodeProvider) Execute(state *EvalState) error {
	return state.forEachModule(n.Module(), func(mi *ModuleInstance) error {
		val, err := state.evalBlock(mi.scope, n.Config, NoInstanceData)
		if err != nil {
			return err
		}
		mi.scope.providers[n.Name] = val
		return nil
	})
}

var _ Referencer = (*NodeOutput)(nil)
var _ Executable = (*NodeOutput)(nil)

type NodeOutput struct {
	*BaseNode
	*AttributeReferencer
	Name string
}

func (n *NodeOutput) Execute(state *EvalState) error {
	return state.forEachModule(n.Module(), func(mi *ModuleInstance) error {
		val, err := state.evalExpr(mi.scope, n.Attr.underlying.Expr, NoInstanceData)
		if err != nil {
			return err
		}
		mi.scope.outputs[n.Name] = val
		return nil
	})
}

var _ Referencer = (*ResourceNode)(nil)
var _ Executable = (*ResourceNode)(nil)

// Resource or Data block
type ResourceNode struct {
	*BaseNode
	Block *BlockConfig
	Type  string
	Name  string
	Addr  ResourceAddr
}

func (n *ResourceNode) References() []*Ref {
	traversals := dynblock.VariablesHCLDec(n.Block.underlying.Body, n.Block.Spec())
	return travReferences(traversals)
}

func (n *ResourceNode) Execute(state *EvalState) error {
	return state.forEachModule(n.Module(), func(mi *ModuleInstance) error {
		expansion, err := expandBlock(state, mi.scope, n.Block)
		if err != nil {
			return err
		}

		mi.setResourceExpanison(n.Addr, expansion)

		var into map[string]map[string]cty.Value
		switch n.Addr.Mode {
		case ManagedMode:
			into = mi.scope.resources
		case DataMode:
			into = mi.scope.datas
		}
		if into[n.Type] == nil {
			into[n.Type] = make(map[string]cty.Value)
		}
		val, err := n.evalInstances(state, mi.scope, expansion)
		if err != nil {
			return err
		}
		into[n.Type][n.Name] = val
		return nil
	})
}

func (n *ResourceNode) evalInstances(
	state *EvalState, scope *Scope, exp nodeExpansion,
) (cty.Value, error) {
	evalResource := func(key InstanceKey) (cty.Value, error) {
		return n.evalInstance(state, scope, exp.Data(key))
	}

	keyType, keys := exp.Keys()
	switch keyType {
	case NoKeyType:
		instVal, err := evalResource(keys[0])
		if err != nil {
			return cty.NilVal, err
		}
		return instVal, nil
	case IntKeyType:
		elems := make([]cty.Value, 0, len(keys))
		for _, key := range keys {
			instVal, err := evalResource(key)
			if err != nil {
				return cty.NilVal, err
			}
			elems = append(elems, instVal)
		}
		return cty.TupleVal(elems), nil
	case StringKeyType:
		attrs := make(map[string]cty.Value)
		for _, key := range keys {
			instVal, err := evalResource(key)
			if err != nil {
				return cty.NilVal, err
			}
			attrs[string(key.(StringKey))] = instVal
		}
		return cty.ObjectVal(attrs), nil
	default:
		return cty.NilVal, fmt.Errorf("unexpected instance key type %d", keyType)
	}
}

func (n *ResourceNode) evalInstance(
	state *EvalState, scope *Scope, data InstanceData,
) (cty.Value, error) {
	val, err := state.evalBlock(scope, n.Block, data)
	if err != nil {
		return cty.NilVal, err
	}
	return val, nil
}

var _ Referencer = (*NodeModuleCall)(nil)
var _ Executable = (*NodeModuleCall)(nil)

type NodeModuleCall struct {
	*BaseNode
	Block *BlockConfig
	Name  string
	Call  *ModuleCall
}

func (n *NodeModuleCall) ID() string {
	return n.id + ":enter"
}

func (n *NodeModuleCall) References() []*Ref {
	var refs []*Ref
	if attr, ok := n.Block.attrs["count"]; ok {
		refs = append(refs, exprReferences(attr.underlying.Expr)...)
	}
	if attr, ok := n.Block.attrs["for_each"]; ok {
		refs = append(refs, exprReferences(attr.underlying.Expr)...)
	}
	return refs
}

func (n *NodeModuleCall) Execute(state *EvalState) error {
	return state.forEachModule(n.Module(), func(mi *ModuleInstance) error {
		exp, err := expandBlock(state, mi.scope, n.Block)
		if err != nil {
			return err
		}
		mi.setModuleExpansion(n.Name, exp)
		return nil
	})
}

type NodeModuleExit struct {
	*BaseNode
}

func (n *NodeModuleExit) ID() string {
	return n.id + ":exit"
}

func expandBlock(state *EvalState, scope *Scope, block *BlockConfig) (nodeExpansion, error) {
	if attr, exists := block.attrs["count"]; exists {
		countVal, err := state.evalExpr(scope, attr.underlying.Expr, NoInstanceData)
		if err != nil {
			return nil, err
		}
		count, err := expandCount(countVal)
		if err != nil {
			return nil, err
		}
		return expansionCount(count), nil
	} else if attr, exists := block.attrs["for_each"]; exists {
		forEachVal, err := state.evalExpr(scope, attr.underlying.Expr, NoInstanceData)
		if err != nil {
			return nil, err
		}
		data, err := expandForEach(forEachVal)
		if err != nil {
			return nil, err
		}
		return expansionForEach(data), nil
	} else {
		return ExpansionSingle, nil
	}
}
