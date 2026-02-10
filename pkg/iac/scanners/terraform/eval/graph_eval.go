package eval

import (
	"fmt"
	"log/slog"
	"maps"
	"path/filepath"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/dynblock"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/hashicorp/hcl/v2/hcldec"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser/funcs"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/terraform/context"
	"github.com/aquasecurity/trivy/pkg/log"
)

type GraphEvaluator struct {
	graph  *graph
	state  *EvalState
	logger *log.Logger
}

type EvalOpts struct {
	Logger *log.Logger

	Workspace         string
	WorkDir           string
	AllowDownloads    bool
	SkipCachedModules bool

	InputVars map[string]cty.Value
}

func NewEvaluator(graph *graph, rootModule *ModuleConfig, opts *EvalOpts) *GraphEvaluator {
	e := &GraphEvaluator{
		graph:  graph,
		state:  newEvalState(graph, rootModule, opts),
		logger: opts.Logger.With(log.Prefix("evaluator")),
	}
	return e
}

func (e *GraphEvaluator) EvalGraph(g *graph) error {
	order, err := g.TopoSort()
	if err != nil {
		return err
	}

	orderStr := make([]string, len(order))
	for i, n := range order {
		orderStr[i] = n.ID()
	}
	e.logger.Debug("Start eval", slog.Any("order", orderStr))
	if err := e.eval(order); err != nil {
		return err
	}
	return nil
}

func (e *GraphEvaluator) eval(order []Node) error {
	for _, node := range order {
		evaluatable, ok := node.(Executable)
		if !ok {
			continue
		}
		id := node.ID()
		e.logger.Debug("Execute node", slog.String("id", id))
		if err := evaluatable.Execute(e.state); err != nil {
			e.logger.Debug("Failed to execute node", log.String("node", node.ID()), log.Err(err))
			continue
		}
	}
	return nil
}

func (e *GraphEvaluator) BuildTerraformModels() terraform.Modules {
	return e.buildModules(nil, e.state.root, NoKeyType, NoInstanceData)
}

func (e *GraphEvaluator) buildModules(parent *terraform.Module, mi *ModuleInstance, keyType KeyInstanceType, data InstanceData) terraform.Modules {
	modConfig := e.state.config.Descendant(mi.scope.addr.Module())
	ret := make(terraform.Modules, 0, len(mi.childInstances)+1)

	scopeCtx := e.buildModuleScopeContext(mi)
	modInstCtx := e.buildInstanceScopeContext(scopeCtx, keyType, data)
	var blocks []*terraform.Block
	var modBlock *terraform.Block

	if !mi.scope.addr.IsRoot() {
		var modBlockIndex cty.Value
		if key := mi.scope.addr.Last().Key; key != NoKey {
			modBlockIndex = key.Value()
		}
		modBlock = terraform.NewBlock(
			modConfig.Block.underlying,
			context.NewContext(modInstCtx, nil),
			nil, nil,
			modConfig.LogicalSource,
			modConfig.FS, modBlockIndex,
		)
		blocks = append(blocks, modBlock)
	}

	for _, block := range modConfig.Blocks {
		blockType := block.underlying.Type
		switch blockType {
		case "resource", "data":
			resType := block.underlying.Labels[0]
			resName := block.underlying.Labels[1]
			addr := ResourceAddr{Mode: modeByBlockType(blockType), Type: resType, Name: resName}
			mi.forEachResource(addr, func(keyType KeyInstanceType, key InstanceKey, data InstanceData) error {
				blockCtx := e.buildInstanceScopeContext(scopeCtx, keyType, data)
				var index cty.Value
				if key != NoKey {
					index = key.Value()
				}

				block := terraform.NewBlock(
					block.underlying, context.NewContext(blockCtx, nil),
					modBlock, nil, modConfig.LogicalSource, modConfig.FS, index,
				)
				blocks = append(blocks, block)
				return nil
			})
		case "variable", "provider", "module", "output":
			blockCtx := e.buildInstanceScopeContext(scopeCtx, NoKeyType, NoInstanceData)
			block := terraform.NewBlock(
				block.underlying, context.NewContext(blockCtx, nil),
				modBlock, nil, modConfig.LogicalSource, modConfig.FS,
			)
			blocks = append(blocks, block)
		}
	}

	module := terraform.NewModule(e.state.config.Dir, modConfig.FS, modConfig.Dir, blocks, nil)
	module.SetParent(parent)

	ret = append(ret, module)
	// e.state.forEachModule()
	for step, childInst := range mi.childInstances {
		exp := mi.moduleCalls[step.Name]
		keyType, _ := exp.Keys()
		childModules := e.buildModules(module, childInst, keyType, exp.Data(step.Key))
		ret = append(ret, childModules...)
	}
	return ret
}

func (e *GraphEvaluator) buildModuleScopeContext(mi *ModuleInstance) *hcl.EvalContext {
	scope := mi.scope
	vals := map[string]cty.Value{}
	maps.Copy(vals, buildResourceObjects(scope.resources))
	vals["local"] = cty.ObjectVal(scope.locals)
	vals["var"] = cty.ObjectVal(scope.vars)
	vals["output"] = cty.ObjectVal(scope.outputs)
	vals["data"] = cty.ObjectVal(buildResourceObjects(scope.datas))
	modules := make(map[string]cty.Value)

	mod := e.state.config.Descendant(scope.addr.Module())
	if mod == nil {
		panic(fmt.Sprintf("module config %s not found", scope.addr.Module().Key()))
	}

	for name := range mi.moduleCalls {
		modules[name] = e.state.prepareModules(mi, name)
	}
	vals["module"] = cty.ObjectVal(modules)

	vals["path"] = cty.ObjectVal(map[string]cty.Value{
		"root":   cty.StringVal(filepath.ToSlash(e.state.config.Dir)),
		"cwd":    cty.StringVal(filepath.ToSlash(e.state.opts.WorkDir)),
		"module": cty.StringVal(filepath.ToSlash(mod.Dir)),
	})

	vals["terraform"] = cty.ObjectVal(map[string]cty.Value{
		"workspace": cty.StringVal(e.state.opts.Workspace),
	})

	return &hcl.EvalContext{
		Functions: funcs.Functions(mod.FS, mod.Dir),
		Variables: vals,
	}
}

func (e *GraphEvaluator) buildInstanceScopeContext(parent *hcl.EvalContext, keyType KeyInstanceType, data InstanceData) *hcl.EvalContext {
	childCtx := parent.NewChild()

	vars := make(map[string]cty.Value)
	switch keyType {
	case IntKeyType:
		vars["count"] = cty.ObjectVal(map[string]cty.Value{
			"index": data.count,
		})
	case StringKeyType:
		vars["each"] = cty.ObjectVal(map[string]cty.Value{
			"key":   data.eachKey,
			"value": data.eachValue,
		})
	}
	childCtx.Variables = vars
	return childCtx
}

func decodeVarType(expr hcl.Expression) (cty.Type, *typeexpr.Defaults, error) {
	// Special-case the shortcuts for list(any) and map(any) which aren't hcl.
	switch hcl.ExprAsKeyword(expr) {
	case "list":
		return cty.List(cty.DynamicPseudoType), nil, nil
	case "map":
		return cty.Map(cty.DynamicPseudoType), nil, nil
	}

	t, def, diag := typeexpr.TypeConstraintWithDefaults(expr)
	if diag.HasErrors() {
		return cty.NilType, nil, diag
	}
	return t, def, nil
}

type Scope struct {
	addr    ModuleInstanceAddr
	locals  map[string]cty.Value
	vars    map[string]cty.Value
	outputs map[string]cty.Value

	providers map[string]cty.Value

	resources map[string]map[string]cty.Value
	datas     map[string]map[string]cty.Value
}

func newScope(addr ModuleInstanceAddr) *Scope {
	return &Scope{
		addr:      addr,
		locals:    make(map[string]cty.Value),
		vars:      make(map[string]cty.Value),
		outputs:   make(map[string]cty.Value),
		providers: make(map[string]cty.Value),
		resources: make(map[string]map[string]cty.Value),
		datas:     make(map[string]map[string]cty.Value),
	}
}

type ModuleInstance struct {
	scope          *Scope
	parent         *ModuleInstance
	moduleCalls    map[string]nodeExpansion
	resources      map[ResourceAddr]nodeExpansion
	childInstances map[ModuleAddrStep]*ModuleInstance
}

func newModuleInstance(addr ModuleInstanceAddr, parent *ModuleInstance) *ModuleInstance {
	return &ModuleInstance{
		scope:          newScope(addr),
		parent:         parent,
		moduleCalls:    make(map[string]nodeExpansion),
		resources:      make(map[ResourceAddr]nodeExpansion),
		childInstances: make(map[ModuleAddrStep]*ModuleInstance),
	}
}

func (m *ModuleInstance) setModuleExpansion(callName string, exp nodeExpansion) {
	m.moduleCalls[callName] = exp
	_, keys := exp.Keys()
	for _, key := range keys {
		step := ModuleAddrStep{Name: callName, Key: key}
		childInst := newModuleInstance(m.scope.addr.Child(callName, key), m)
		m.childInstances[step] = childInst
	}
}

func (m *ModuleInstance) setResourceExpanison(addr ResourceAddr, exp nodeExpansion) {
	m.resources[addr] = exp
}

func (m *ModuleInstance) forEachResource(addr ResourceAddr, fn func(keyType KeyInstanceType, key InstanceKey, data InstanceData) error) error {
	exp, ok := m.resources[addr]
	if !ok {
		return fmt.Errorf("uknown resource %s in module %s", addr.Key(), m.scope.addr.Key())
	}

	var errs error
	keyType, keys := exp.Keys()
	for _, key := range keys {
		data := exp.Data(key)
		if err := fn(keyType, key, data); err != nil {
			errs = multierror.Append(errs, err)
		}
	}

	return errs

}

func (m *ModuleInstance) moduleInstances(addr ModuleAddr, parentAddr ModuleInstanceAddr) []*ModuleInstance {
	if len(addr) > 0 {
		name := addr[0]
		var instances []*ModuleInstance
		for step, inst := range m.childInstances {
			if step.Name != name {
				continue
			}
			instAddr := append(parentAddr, step)
			instances = append(instances, inst.moduleInstances(addr[1:], instAddr)...)
		}
		return instances
	}

	return []*ModuleInstance{m}
}

func (m *ModuleInstance) instanceData() (InstanceData, error) {
	if m.parent == nil {
		return NoInstanceData, nil
	}
	lastStep := m.scope.addr.Last()
	expansion, ok := m.parent.moduleCalls[lastStep.Name]
	if !ok {
		return NoInstanceData, fmt.Errorf("module %s not expanded", m.scope.addr.Key())
	}
	return expansion.Data(lastStep.Key), nil
}

type EvalState struct {
	opts *EvalOpts

	graph  *graph
	root   *ModuleInstance
	config *ModuleConfig
}

func newEvalState(g *graph, config *ModuleConfig, opts *EvalOpts) *EvalState {
	return &EvalState{
		opts:   opts,
		graph:  g,
		root:   newModuleInstance(RootModuleInstanceAddr, nil),
		config: config,
	}
}

func (s *EvalState) findModuleInstance(addr ModuleInstanceAddr) (*ModuleInstance, error) {
	mod := s.root
	for i, step := range addr {
		next, ok := mod.childInstances[step]
		if !ok {
			return nil, fmt.Errorf("child instance %s for %s", step.Name, addr[:i].Key())
		}
		mod = next
	}
	return mod, nil
}

func (s *EvalState) forEachModule(addr ModuleAddr, fn func(*ModuleInstance) error) error {
	if addr.IsRoot() {
		return fn(s.root)
	}

	var errs error
	for _, inst := range s.root.moduleInstances(addr, nil) {
		if err := fn(inst); err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	return errs
}

func mergeSpec(a, b hcldec.Spec) hcldec.Spec {
	switch a := a.(type) {
	case hcldec.ObjectSpec:
		b, ok := b.(hcldec.ObjectSpec)
		if !ok {
			return a
		}
		maps.Copy(a, b)
		return a
	case *hcldec.AttrSpec, *hcldec.BlockSpec, *hcldec.BlockTupleSpec:
		return a
	default:
		panic(fmt.Sprintf("unexpected spec type: %T", a))
	}
}

func (s *EvalState) expandBlock(scope *Scope, block *BlockConfig, data InstanceData) (hcl.Body, error) {
	// collect refs only for for_each
	// TODO: expand dyn block
	spec := block.Spec()
	traversals := dynblock.ExpandVariablesHCLDec(block.underlying.Body, spec)
	refs := travReferences(traversals)
	evalCtx := s.evalCtx(scope, refs, data)
	expanded := dynblock.Expand(block.underlying.Body, evalCtx)
	return expanded, nil
}

func (s *EvalState) evalBlock(scope *Scope, config *BlockConfig, data InstanceData) (cty.Value, error) {
	body, err := s.expandBlock(scope, config, data)
	if err != nil {
		// TODO: log
		return cty.NilVal, err
	}

	traversals := dynblock.VariablesHCLDec(body, config.Spec())
	refs := travReferences(traversals)
	evalCtx := s.evalCtx(scope, refs, data)
	return cty.ObjectVal(config.ToValue(evalCtx)), nil
}

func (s *EvalState) evalExpr(scope *Scope, expr hcl.Expression, data InstanceData) (cty.Value, error) {
	evalCtx := s.evalCtx(scope, exprReferences(expr), data)
	val, diags := expr.Value(evalCtx)
	if diags.HasErrors() {
		return cty.DynamicVal, nil
	}
	return val, nil
}

func (s *EvalState) evalCtx(scope *Scope, refs []*Ref, data InstanceData) *hcl.EvalContext {
	locals := make(map[string]cty.Value)
	vars := make(map[string]cty.Value)
	outputs := make(map[string]cty.Value)
	forEach := make(map[string]cty.Value)
	count := make(map[string]cty.Value)
	modules := make(map[string]cty.Value)
	datas := make(map[string]map[string]cty.Value)
	managed := make(map[string]map[string]cty.Value)

	// TODO: If the expression refers to a non-existent object, evaluating it may return a null value,
	// which can cause unexpected behavior or panics when working with the cty package.
	// We should resolve the value step by step via the reference and return cty.DynamicValue
	// if any part of the traversal is missing.
	//
	// The remaining traversal must be preserved in the reference to correctly determine
	// whether the value actually exists.
	for _, ref := range refs {
		addr := ref.Addr
		switch a := addr.(type) {
		case ModuleCallOutputAddr:
			addr = a.Call
		}

		switch a := addr.(type) {
		case ForEachAddr:
			switch a.Name {
			case "key":
				forEach[a.Name] = data.eachKey
			case "value":
				forEach[a.Name] = data.eachValue
			default:
				forEach[a.Name] = cty.DynamicVal
			}
		case CountAddr:
			count[a.Name] = data.count
		case LocalAddr:
			val, ok := scope.locals[a.Name]
			if !ok {
				val = cty.DynamicVal
			}
			locals[a.Name] = val
		case VariableAddr:
			val, ok := scope.vars[a.Name]
			if !ok {
				val = cty.DynamicVal
			}
			vars[a.Name] = val
		case OutputAddr:
			val, ok := scope.outputs[a.Name]
			if !ok {
				val = cty.DynamicVal
			}
			outputs[a.Name] = val
		case ModuleCallAddr:
			modInst, err := s.findModuleInstance(scope.addr)
			if err != nil {
				// It should never happen.
				panic(fmt.Errorf("module %s not found", scope.addr.Key()))
			}
			modules[a.Name] = s.prepareModules(modInst, a.Name)
			// TODO: get vars from nested scope by instance key from remaining travesal
		case ResourceAddr:
			var from map[string]map[string]cty.Value
			var into map[string]map[string]cty.Value
			switch a.Mode {
			case DataMode:
				from = scope.datas
				into = datas
			case ManagedMode:
				from = scope.resources
				into = managed
			}

			if into[a.Type] == nil {
				into[a.Type] = make(map[string]cty.Value)
			}
			into[a.Type][a.Name] = from[a.Type][a.Name]
		default:
			log.Debug("unsupported addr type", log.Any("type", fmt.Sprintf("%T", addr)))
		}
	}

	vals := map[string]cty.Value{}
	maps.Copy(vals, buildResourceObjects(managed))
	vals["local"] = cty.ObjectVal(locals)
	vals["var"] = cty.ObjectVal(vars)
	vals["output"] = cty.ObjectVal(outputs)
	vals["module"] = cty.ObjectVal(modules)
	vals["data"] = cty.ObjectVal(buildResourceObjects(scope.datas))
	vals["each"] = cty.ObjectVal(forEach)
	vals["count"] = cty.ObjectVal(count)

	mod := s.config.Descendant(scope.addr.Module())
	if mod == nil {
		panic(fmt.Sprintf("module config %s not found", scope.addr.Module().Key()))
	}

	vals["path"] = cty.ObjectVal(map[string]cty.Value{
		"root":   cty.StringVal(filepath.ToSlash(s.config.Dir)),
		"cwd":    cty.StringVal(filepath.ToSlash(s.opts.WorkDir)),
		"module": cty.StringVal(filepath.ToSlash(mod.Dir)),
	})

	vals["terraform"] = cty.ObjectVal(map[string]cty.Value{
		"workspace": cty.StringVal(s.opts.Workspace),
	})

	return &hcl.EvalContext{
		Functions: funcs.Functions(mod.FS, mod.Dir),
		Variables: vals,
	}
}

func (s *EvalState) prepareModules(modInst *ModuleInstance, name string) cty.Value {
	evalModule := func(key InstanceKey) cty.Value {
		step := ModuleAddrStep{
			Name: name,
			Key:  key,
		}
		inst := modInst.childInstances[step]
		return cty.ObjectVal(inst.scope.outputs)
	}

	// reference to an unknown module
	exp, ok := modInst.moduleCalls[name]
	if !ok {
		return cty.DynamicVal
	}

	keyType, instKeys := exp.Keys()
	switch keyType {
	case NoKeyType:
		return evalModule(instKeys[0])
	case IntKeyType:
		elems := make([]cty.Value, 0, len(instKeys))
		for _, key := range instKeys {
			elems = append(elems, evalModule(key))
		}
		return cty.TupleVal(elems)
	case StringKeyType:
		attrs := make(map[string]cty.Value, len(instKeys))
		for _, instKey := range instKeys {
			key := string(instKey.(StringKey))
			attrs[key] = evalModule(instKey)
		}
		return cty.ObjectVal(attrs)
	default:
		panic("unreachable")
	}
}

func buildResourceObjects(resources map[string]map[string]cty.Value) map[string]cty.Value {
	vals := make(map[string]cty.Value)
	for typeName, nameVals := range resources {
		vals[typeName] = cty.ObjectVal(nameVals)
	}
	return vals
}
