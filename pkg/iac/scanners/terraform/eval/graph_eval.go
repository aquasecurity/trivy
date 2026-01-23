package eval

import (
	"fmt"
	"log/slog"
	"maps"
	"path/filepath"

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

func NewEvaluator(graph *graph, rootModule *ModuleConfig, workDir, workspace string) *GraphEvaluator {
	return &GraphEvaluator{
		graph:  graph,
		state:  newEvalState(graph, rootModule, workDir, workspace),
		logger: log.WithPrefix("evaluator"),
	}
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
			return fmt.Errorf("execute %s node: %w", node.ID(), err)
		}
	}
	return nil
}

func (e *GraphEvaluator) BuildTerraformModels() terraform.Modules {
	return e.buildModules(e.state.root, NoKeyType, NoInstanceData)
}

func (e *GraphEvaluator) buildModules(mi *ModuleInstance, keyType KeyInstanceType, data InstanceData) terraform.Modules {
	modConfig := e.state.config.Descendant(mi.scope.addr.Module())
	ret := make(terraform.Modules, 0, len(mi.childInstances)+1)

	scopeCtx := e.buildModuleScopeContext(mi.scope)
	modInstCtx := e.buildInstanceContext(scopeCtx, keyType, data)
	var blocks []*terraform.Block
	var modBlockIndex cty.Value
	var modSource string
	var modBlock *terraform.Block

	if !mi.scope.addr.IsRoot() {
		modBlockIndex = mi.scope.addr.Last().Key.Value()
		modSource = modConfig.Parent.ModuleCalls[modConfig.Name].Source.String()
		modBlock = terraform.NewBlock(
			modConfig.Block.underlying, context.NewContext(modInstCtx, nil),
			nil, nil, modSource, modConfig.FS, modBlockIndex,
		)
		blocks = append(blocks, modBlock)
	}

	for _, block := range modConfig.Blocks {
		switch block.underlying.Type {
		case "resource", "data", "variable":
			// TODO: get index from expansion
			blockCtx := e.buildInstanceContext(scopeCtx, NoKeyType, NoInstanceData)
			block := terraform.NewBlock(
				block.underlying, context.NewContext(blockCtx, nil),
				modBlock, nil, modSource, modConfig.FS,
			)
			blocks = append(blocks, block)
		}
	}

	ret = append(ret, terraform.NewModule(e.state.config.Dir, modConfig.FS, modConfig.Dir, blocks, nil))
	for step, childInst := range mi.childInstances {
		exp := mi.moduleCalls[step.Name]
		keyType, _ := exp.Keys()
		childModules := e.buildModules(childInst, keyType, exp.Data(step.Key))
		ret = append(ret, childModules...)
	}
	return ret
}

func (e *GraphEvaluator) buildModuleScopeContext(scope *Scope) *hcl.EvalContext {
	vals := map[string]cty.Value{}
	maps.Copy(vals, buildResourceObjects(scope.resources))
	vals["local"] = cty.ObjectVal(scope.locals)
	vals["var"] = cty.ObjectVal(scope.vars)
	vals["output"] = cty.ObjectVal(scope.outputs)
	vals["data"] = cty.ObjectVal(buildResourceObjects(scope.datas))
	// vals["module"] = cty.ObjectVal(modules)

	mod := e.state.config.Descendant(scope.addr.Module())
	if mod == nil {
		panic(fmt.Sprintf("module config %s not found", scope.addr.Module().Key()))
	}

	vals["path"] = cty.ObjectVal(map[string]cty.Value{
		"root":   cty.StringVal(filepath.ToSlash(e.state.config.Dir)),
		"cwd":    cty.StringVal(filepath.ToSlash(e.state.workDir)),
		"module": cty.StringVal(filepath.ToSlash(mod.Dir)),
	})

	vals["terraform"] = cty.ObjectVal(map[string]cty.Value{
		"workspace": cty.StringVal(e.state.workspace),
	})

	return &hcl.EvalContext{
		Functions: funcs.Functions(mod.FS, mod.Dir),
		Variables: vals,
	}
}

func (e *GraphEvaluator) buildInstanceContext(parent *hcl.EvalContext, keyType KeyInstanceType, data InstanceData) *hcl.EvalContext {
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

func expandCount(countVal cty.Value) (int, error) {
	if countVal.IsNull() || !countVal.IsKnown() || countVal.Type() != cty.Number {
		return -1, fmt.Errorf("count is null, unkown or not a number")
	}
	count, _ := countVal.AsBigFloat().Int64()
	return int(count), nil
}

func expandForEach(forEachVal cty.Value) (map[string]cty.Value, error) {
	if forEachVal.IsNull() || !forEachVal.IsKnown() {
		return nil, fmt.Errorf("for-each is null or unkown")
	}
	if !forEachVal.CanIterateElements() {
		// TODO: log
		return nil, nil
	}

	data := make(map[string]cty.Value)
	it := forEachVal.ElementIterator()
	for it.Next() {
		key, val := it.Element()
		if key.IsNull() || !key.IsKnown() {
			continue
		}
		if val.IsNull() || !val.IsKnown() {
			continue
		}

		if key.Type() != cty.String {
			continue
		}

		// TODO: tf allows only a map, or set of strings
		switch {
		case forEachVal.Type().IsSetType():
			// TODO: convert val to string
			data[val.AsString()] = val
		case forEachVal.Type().IsObjectType(), forEachVal.Type().IsMapType():
			data[key.AsString()] = val
		default:
			return nil, nil
		}
	}
	return data, nil
}

type Scope struct {
	addr    ModuleInstanceAddr
	locals  map[string]cty.Value
	vars    map[string]cty.Value
	outputs map[string]cty.Value

	resources map[string]map[string]cty.Value
	datas     map[string]map[string]cty.Value
}

func newScope(addr ModuleInstanceAddr) *Scope {
	return &Scope{
		addr:      addr,
		locals:    make(map[string]cty.Value),
		vars:      make(map[string]cty.Value),
		outputs:   make(map[string]cty.Value),
		resources: make(map[string]map[string]cty.Value),
		datas:     make(map[string]map[string]cty.Value),
	}
}

type InstanceData struct {
	count     cty.Value
	eachKey   cty.Value
	eachValue cty.Value
}

type KeyInstanceType int

const (
	NoKeyType KeyInstanceType = iota
	StringKeyType
	IntKeyType
)

type nodeExpansion interface {
	Keys() (KeyInstanceType, []InstanceKey)
	Data(key InstanceKey) InstanceData
}

var ExpansionSingle = expansionSingle{}
var noKeys = []InstanceKey{NoKey}

type expansionSingle struct{}

func (e expansionSingle) Keys() (KeyInstanceType, []InstanceKey) {
	return NoKeyType, noKeys
}

func (e expansionSingle) Data(key InstanceKey) InstanceData {
	return InstanceData{}
}

type expansionCount int

func (e expansionCount) Keys() (KeyInstanceType, []InstanceKey) {
	keys := make([]InstanceKey, 0, e)
	for i := range e {
		keys = append(keys, IntKey(i))
	}
	return IntKeyType, keys
}

func (e expansionCount) Data(key InstanceKey) InstanceData {
	return InstanceData{
		count: cty.NumberIntVal(int64(key.(IntKey))),
	}
}

type expansionForEach map[string]cty.Value

func (e expansionForEach) Keys() (KeyInstanceType, []InstanceKey) {
	keys := make([]InstanceKey, 0, len(e))
	for k := range e {
		keys = append(keys, StringKey(k))
	}
	return StringKeyType, keys
}

func (e expansionForEach) Data(key InstanceKey) InstanceData {
	k := string(key.(StringKey))
	v := e[k]
	return InstanceData{
		eachKey:   key.Value(),
		eachValue: v,
	}
}

var NoInstanceData = InstanceData{}

type ModuleInstance struct {
	scope          *Scope
	parent         *ModuleInstance
	moduleCalls    map[string]nodeExpansion
	childInstances map[ModuleAddrStep]*ModuleInstance
}

func newModuleInstance(addr ModuleInstanceAddr, parent *ModuleInstance) *ModuleInstance {
	return &ModuleInstance{
		scope:          newScope(addr),
		parent:         parent,
		moduleCalls:    make(map[string]nodeExpansion),
		childInstances: make(map[ModuleAddrStep]*ModuleInstance),
	}
}

func (m *ModuleInstance) SetModuleExpansion(callName string, expansion nodeExpansion) {
	m.moduleCalls[callName] = expansion
	_, keys := expansion.Keys()
	for _, key := range keys {
		step := ModuleAddrStep{Name: callName, Key: key}
		childInst := newModuleInstance(m.scope.addr.Child(callName, key), m)
		m.childInstances[step] = childInst
	}
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

func (m *ModuleInstance) InstanceData() (InstanceData, error) {
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
	workDir   string
	workspace string
	graph     *graph
	root      *ModuleInstance
	config    *ModuleConfig
}

var rootModuleInst = newModuleInstance(RootModuleInstanceAddr, nil)

func newEvalState(g *graph, config *ModuleConfig, workDir, workspace string) *EvalState {
	return &EvalState{
		workDir:   workDir,
		workspace: workspace,
		graph:     g,
		root:      rootModuleInst,
		config:    config,
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

	for _, inst := range s.root.moduleInstances(addr, nil) {
		// TODO: collect errors
		if err := fn(inst); err != nil {
			return err
		}
	}
	return nil
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

func (s *EvalState) evalBlock(scope *Scope, block *BlockConfig, data InstanceData) (cty.Value, error) {
	body, err := s.expandBlock(scope, block, data)
	if err != nil {
		// TODO: log
		return cty.NilVal, err
	}

	traversals := dynblock.VariablesHCLDec(body, block.Spec())
	refs := travReferences(traversals)
	evalCtx := s.evalCtx(scope, refs, data)
	return cty.ObjectVal(block.ToValue(evalCtx)), nil
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
			locals[a.Name] = scope.locals[a.Name]
		case VariableAddr:
			vars[a.Name] = scope.vars[a.Name]
		case OutputAddr:
			outputs[a.Name] = scope.outputs[a.Name]
		case ModuleCallAddr:
			modInst, err := s.findModuleInstance(scope.addr)
			if err != nil {
				panic(err.Error())
			}
			evalModule := func(key InstanceKey) cty.Value {
				step := ModuleAddrStep{
					Name: a.Name,
					Key:  key,
				}
				inst := modInst.childInstances[step]
				return cty.ObjectVal(inst.scope.outputs)
			}

			exp := modInst.moduleCalls[a.Name]
			keyType, instKeys := exp.Keys()
			switch keyType {
			case NoKeyType:
				modules[a.Name] = evalModule(instKeys[0])
			case IntKeyType:
				elems := make([]cty.Value, 0, len(instKeys))
				for _, key := range instKeys {
					elems = append(elems, evalModule(key))
				}
				modules[a.Name] = cty.TupleVal(elems)
			case StringKeyType:
				attrs := make(map[string]cty.Value, len(instKeys))
				for _, instKey := range instKeys {
					key := string(instKey.(StringKey))
					attrs[key] = evalModule(instKey)
				}
				modules[a.Name] = cty.ObjectVal(attrs)
			}
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
		"cwd":    cty.StringVal(filepath.ToSlash(s.workDir)),
		"module": cty.StringVal(filepath.ToSlash(mod.Dir)),
	})

	vals["terraform"] = cty.ObjectVal(map[string]cty.Value{
		"workspace": cty.StringVal(s.workspace),
	})

	return &hcl.EvalContext{
		Functions: funcs.Functions(mod.FS, mod.Dir),
		Variables: vals,
	}
}

func buildResourceObjects(resources map[string]map[string]cty.Value) map[string]cty.Value {
	vals := make(map[string]cty.Value)
	for typeName, nameVals := range resources {
		vals[typeName] = cty.ObjectVal(nameVals)
	}
	return vals
}
