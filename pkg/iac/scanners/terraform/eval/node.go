package eval

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"strings"

	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/dynblock"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/aquasecurity/trivy/pkg/log"
)

type Referencer interface {
	// TODO: return an iter.Seq
	References() []*Ref
}

type Executable interface {
	Execute(state *evalState) error
}

type Node interface {
	ID() string
	Module() ModuleAddr
}

type BaseNode struct {
	id         string
	moduleAddr ModuleAddr
}

func newBaseNode(addr Address, moduleAddr ModuleAddr) BaseNode {
	return BaseNode{
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

type NodeRoot struct{}

func (n *NodeRoot) ID() string {
	return "<root>"
}

func (n *NodeRoot) Module() ModuleAddr {
	return ModuleAddr{}
}

var _ Executable = (*NodeRootVariable)(nil)

type NodeRootVariable struct {
	BaseNode
	Name    string
	Default *AttrConfig
	Type    *AttrConfig
}

func (n *NodeRootVariable) Execute(state *evalState) error {
	return state.forEachModule(n.Module(), func(mi *ModuleInstance) error {
		val := cty.DynamicVal
		var evalErr error

		// TODO: handle nullable variables
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
			// Root variable value is missing. We already log missing variables before evaluation,
			// so here we just treat the variable as unknown.
			val = cty.DynamicVal
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
	BaseNode
	AttributeReferencer
	Name    string
	Default *AttrConfig
	Type    *AttrConfig
}

func (n *NodeVariable) Execute(state *evalState) error {
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

		// TODO: investigate. if the type of the variable is known, it is better to use an
		// unknown value with this type instead of a dynamic value.

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
		return cty.DynamicVal, fmt.Errorf(
			"failed to decode variable type at %s: %w",
			ctx,
			err,
		)
	}

	if defaults != nil {
		val = defaults.Apply(val)
	}

	typedVal, err := convertValue(val, valType)
	if err != nil {
		return cty.DynamicVal, fmt.Errorf(
			"failed to convert value %s to %s at %s: %w",
			val.GoString(),
			valType.FriendlyName(),
			ctx,
			err,
		)
	}

	return typedVal, nil
}

func convertValue(val cty.Value, typ cty.Type) (ret cty.Value, err error) {
	// convert.Convert may cause panic if complex values such as objects or maps contain cty.NilVal.
	defer func() {
		if r := recover(); r != nil {
			log.Debug(
				"panic recovered during cty value conversion",
				"target_type", typ.FriendlyName(),
				"value", val,
				"panic", r,
			)

			// fallback to the original value
			ret = val
		}
	}()

	typedVal, err := convert.Convert(val, typ)
	if err != nil {
		return cty.DynamicVal, err
	}

	return typedVal, nil
}

var _ Referencer = (*NodeLocal)(nil)
var _ Executable = (*NodeLocal)(nil)

type NodeLocal struct {
	BaseNode
	AttributeReferencer
	Name string
}

func (n *NodeLocal) Execute(state *evalState) error {
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
	BaseNode
	Name   string
	Config *BlockConfig
}

func (n *NodeProvider) References() []*Ref {
	traversals := dynblock.VariablesHCLDec(n.Config.underlying.Body, n.Config.Spec())
	return travReferences(traversals)
}

func (n *NodeProvider) Execute(state *evalState) error {
	return state.forEachModule(n.Module(), func(mi *ModuleInstance) error {
		// TODO: if an error occurs, set a dynamic value or unknown value
		val, err := state.evalBlock(mi.scope, n.Config.underlying.Body, n.Config.Spec(), NoInstanceData)
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
	BaseNode
	AttributeReferencer
	Name string
}

func (n *NodeOutput) Execute(state *evalState) error {
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

// ResourceNode represents a resource or block of data in the configuration
type ResourceNode struct {
	BaseNode
	Block *BlockConfig
	Type  string
	Name  string
	Addr  ResourceAddr
}

func (n *ResourceNode) References() []*Ref {
	traversals := dynblock.VariablesHCLDec(n.Block.underlying.Body, n.Block.Spec())
	return travReferences(traversals)
}

func (n *ResourceNode) Execute(state *evalState) error {
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

		var evalErr error

		val, err := n.evalInstances(state, mi.scope, expansion)
		if err != nil {
			evalErr = multierror.Append(evalErr, err)
		}

		into[n.Type][n.Name] = val
		return nil
	})
}

func (n *ResourceNode) evalInstances(
	state *evalState, scope *Scope, exp nodeExpansion,
) (cty.Value, error) {
	evalResource := func(key InstanceKey) (cty.Value, error) {
		return n.evalInstance(state, scope, key, exp.Data(key))
	}

	keyType, keys := exp.Keys()
	switch keyType {
	case NoKeyType:
		instVal, err := evalResource(keys[0])
		if err != nil {
			return cty.DynamicVal, err
		}
		return instVal, nil
	case IntKeyType:
		elems := make([]cty.Value, 0, len(keys))
		for _, key := range keys {
			instVal, err := evalResource(key)
			if err != nil {
				return cty.DynamicVal, err
			}
			elems = append(elems, instVal)
		}
		return cty.TupleVal(elems), nil
	case StringKeyType:
		attrs := make(map[string]cty.Value)
		for _, key := range keys {
			instVal, err := evalResource(key)
			if err != nil {
				return cty.DynamicVal, err
			}
			attrs[string(key.(StringKey))] = instVal
		}
		return cty.ObjectVal(attrs), nil
	default:
		return cty.DynamicVal, fmt.Errorf("unexpected instance key type %d", keyType)
	}
}

func (n *ResourceNode) evalInstance(
	state *evalState, scope *Scope, key InstanceKey, data InstanceData,
) (cty.Value, error) {
	spec := n.Block.Spec()
	dynBody := state.expandBlock(scope, n.Block, spec, data)

	refinedSpec := refineBlockSpec(dynBody, spec)
	val, err := state.evalBlock(scope, dynBody, refinedSpec, data)
	if err != nil {
		return cty.DynamicVal, err
	}

	instance := &instanceConfig{
		id:   uuid.NewString(),
		body: dynBody,
		spec: spec,
	}

	scope.resourceInstances[n.Addr.Instance(key)] = instance

	if !val.Type().IsObjectType() {
		return val, nil
	}

	unmarkedVal, _ := val.Unmark()
	valueMap := unmarkedVal.AsValueMap()
	if valueMap == nil {
		valueMap = make(map[string]cty.Value)
	}
	typeLabel := n.Block.underlying.Labels[0]
	presets := buildPresetValues(typeLabel, instance.id)
	for name, presetValue := range presets {
		if _, exists := valueMap[name]; !exists {
			valueMap[name] = presetValue
		}
	}

	postValues := buildPostValues(typeLabel, valueMap, instance.id)
	maps.Copy(valueMap, postValues)
	return cty.ObjectVal(valueMap), nil
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

func buildPresetValues(typeLabel string, id string) map[string]cty.Value {
	vals := make(map[string]cty.Value)

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

func buildPostValues(typeLabel string, current map[string]cty.Value, id string) map[string]cty.Value {
	vals := make(map[string]cty.Value)
	if strings.HasPrefix(typeLabel, "aws_s3_bucket") {
		if bucket, ok := current["bucket"]; ok {
			vals["id"] = bucket
		} else {
			vals["bucket"] = cty.StringVal(id)
		}
	}

	if typeLabel == "aws_s3_bucket" {
		var bucketName string
		if bucket := current["bucket"]; !bucket.IsNull() && bucket.IsKnown() && bucket.Type().Equals(cty.String) {
			bucketName = bucket.AsString()
		}
		vals["arn"] = cty.StringVal(fmt.Sprintf("arn:aws:s3:::%s", bucketName))
	}
	return vals
}

var _ Referencer = (*NodeModuleCall)(nil)
var _ Executable = (*NodeModuleCall)(nil)

type NodeModuleCall struct {
	BaseNode
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

func (n *NodeModuleCall) Execute(state *evalState) error {
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
	BaseNode
}

func (n *NodeModuleExit) ID() string {
	return n.id + ":exit"
}

// TODO: Introduce value marks for unexpanded blocks
//
// When a block cannot be fully expanded (e.g., count or for_each is unknown),
// wrap its resulting cty.Value with a mark/capsule indicating:
//   - the block is unexpanded
//   - the source block that caused the unknown value
//   - the reason (e.g., "count unknown", "for_each unknown")
//
// This allows:
//   - tracing which values are affected by unexpanded blocks
//   - propagating unknowns during evaluation
//   - optionally filtering or special-handling results that depend on
//     values originating from unexpanded blocks, to reduce noise
func expandBlock(state *evalState, scope *Scope, block *BlockConfig) (nodeExpansion, error) {
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
