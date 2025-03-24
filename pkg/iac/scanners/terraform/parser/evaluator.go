package parser

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/samber/lo"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/aquasecurity/trivy/pkg/iac/ignore"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	tfcontext "github.com/aquasecurity/trivy/pkg/iac/terraform/context"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	maxContextIterations = 32
)

type evaluator struct {
	logger            *log.Logger
	filesystem        fs.FS
	ctx               *tfcontext.Context
	blocks            terraform.Blocks
	inputVars         map[string]cty.Value
	moduleMetadata    *modulesMetadata
	projectRootPath   string // root of the current scan
	modulePath        string
	moduleName        string
	ignores           ignore.Rules
	parentParser      *Parser
	allowDownloads    bool
	skipCachedModules bool
}

func newEvaluator(
	target fs.FS,
	parentParser *Parser,
	projectRootPath string,
	modulePath string,
	workingDir string,
	moduleName string,
	blocks terraform.Blocks,
	inputVars map[string]cty.Value,
	moduleMetadata *modulesMetadata,
	workspace string,
	ignores ignore.Rules,
	logger *log.Logger,
	allowDownloads bool,
	skipCachedModules bool,
) *evaluator {

	// create a context to store variables and make functions available
	ctx := tfcontext.NewContext(&hcl.EvalContext{
		Functions: Functions(target, modulePath),
	}, nil)

	// these variables are made available by terraform to each module
	ctx.SetByDot(cty.StringVal(workspace), "terraform.workspace")
	ctx.SetByDot(cty.StringVal(projectRootPath), "path.root")
	ctx.SetByDot(cty.StringVal(modulePath), "path.module")
	ctx.SetByDot(cty.StringVal(workingDir), "path.cwd")

	// each block gets its own scope to define variables in
	for _, b := range blocks {
		b.OverrideContext(ctx.NewChild())
	}

	return &evaluator{
		filesystem:        target,
		parentParser:      parentParser,
		modulePath:        modulePath,
		moduleName:        moduleName,
		projectRootPath:   projectRootPath,
		ctx:               ctx,
		blocks:            blocks,
		inputVars:         inputVars,
		moduleMetadata:    moduleMetadata,
		ignores:           ignores,
		logger:            logger,
		allowDownloads:    allowDownloads,
		skipCachedModules: skipCachedModules,
	}
}

func (e *evaluator) evaluateStep() {

	e.ctx.Set(e.getValuesByBlockType("variable"), "var")
	e.ctx.Set(e.getValuesByBlockType("locals"), "local")
	e.ctx.Set(e.getValuesByBlockType("provider"), "provider")

	for typ, resource := range e.getResources() {
		e.ctx.Set(resource, typ)
	}

	e.ctx.Set(e.getValuesByBlockType("data"), "data")
	e.ctx.Set(e.getValuesByBlockType("output"), "output")
	e.ctx.Set(e.getValuesByBlockType("module"), "module")
}

// exportOutputs is used to export module outputs to the parent module
func (e *evaluator) exportOutputs() cty.Value {
	data := make(map[string]cty.Value)
	for _, block := range e.blocks.OfType("output") {
		attr := block.GetAttribute("value")
		if attr.IsNil() {
			continue
		}
		data[block.Label()] = attr.Value()
		e.logger.Debug(
			"Added module output",
			log.String("block", block.Label()),
			log.String("value", attr.Value().GoString()),
		)
	}
	return cty.ObjectVal(data)
}

func (e *evaluator) EvaluateAll(ctx context.Context) (terraform.Modules, map[string]fs.FS) {

	e.logger.Debug("Starting module evaluation...", log.String("path", e.modulePath))

	fsKey := types.CreateFSKey(e.filesystem)
	fsMap := map[string]fs.FS{
		fsKey: e.filesystem,
	}

	e.evaluateSteps()

	// expand out resources and modules via count, for-each and dynamic
	// (not a typo, we do this twice so every order is processed)
	e.blocks = e.expandBlocks(e.blocks)
	e.blocks = e.expandBlocks(e.blocks)

	// rootModule is initialized here, but not fully evaluated until all submodules are evaluated.
	// A pointer for this module is needed up front to correctly set the module parent hierarchy.
	// The actual instance is created at the end, when all terraform blocks
	// are evaluated.
	rootModule := new(terraform.Module)

	submodules := e.evaluateSubmodules(ctx, rootModule, fsMap)

	e.logger.Debug("Starting post-submodules evaluation...")
	e.evaluateSteps()

	e.logger.Debug("Module evaluation complete.")
	// terraform.NewModule must be called at the end, as `e.blocks` can be
	// changed up until the last moment.
	*rootModule = *terraform.NewModule(e.projectRootPath, e.modulePath, e.blocks, e.ignores)
	return append(terraform.Modules{rootModule}, submodules...), fsMap
}

func (e *evaluator) evaluateSubmodules(ctx context.Context, parent *terraform.Module, fsMap map[string]fs.FS) terraform.Modules {
	submodules := e.loadSubmodules(ctx)

	if len(submodules) == 0 {
		return nil
	}

	e.logger.Debug("Starting submodules evaluation...")

	for i := 0; i < maxContextIterations; i++ {
		changed := false
		for _, sm := range submodules {
			changed = changed || e.evaluateSubmodule(ctx, sm)
		}
		if !changed {
			e.logger.Debug("All submodules are evaluated", log.Int("loop", i))
			break
		}
	}

	e.logger.Debug("Starting post-submodule evaluation...")
	e.evaluateSteps()

	var modules terraform.Modules
	for _, sm := range submodules {
		// Assign the parent placeholder to any submodules without a parent. Any modules
		// with a parent already have their correct parent placeholder assigned.
		for _, submod := range sm.modules {
			if submod.Parent() == nil {
				submod.SetParent(parent)
			}
		}

		modules = append(modules, sm.modules...)
		for k, v := range sm.fsMap {
			fsMap[k] = v
		}
	}

	e.logger.Debug("Finished processing submodule(s).", log.Int("count", len(modules)))
	return modules
}

type submodule struct {
	definition *ModuleDefinition
	eval       *evaluator
	modules    terraform.Modules
	lastState  map[string]cty.Value
	fsMap      map[string]fs.FS
}

func (e *evaluator) loadSubmodules(ctx context.Context) []*submodule {
	var submodules []*submodule

	for _, definition := range e.loadModules(ctx) {
		eval, err := definition.Parser.Load(ctx)
		if errors.Is(err, ErrNoFiles) {
			continue
		} else if err != nil {
			e.logger.Error("Failed to load submodule", log.String("name", definition.Name), log.Err(err))
			continue
		}

		submodules = append(submodules, &submodule{
			definition: definition,
			eval:       eval,
			fsMap:      make(map[string]fs.FS),
		})
	}

	return submodules
}

func (e *evaluator) evaluateSubmodule(ctx context.Context, sm *submodule) bool {
	inputVars := sm.definition.inputVars()
	if len(sm.modules) > 0 {
		if reflect.DeepEqual(inputVars, sm.lastState) {
			e.logger.Debug("Submodule inputs unchanged", log.String("name", sm.definition.Name))
			return false
		}
	}

	e.logger.Debug("Evaluating submodule", log.String("name", sm.definition.Name))
	sm.eval.inputVars = inputVars
	sm.modules, sm.fsMap = sm.eval.EvaluateAll(ctx)
	outputs := sm.eval.exportOutputs()

	// lastState needs to be captured after applying outputs – so that they
	// don't get treated as changes – but before running post-submodule
	// evaluation, so that changes from that can trigger re-evaluations of
	// the submodule if/when they feed back into inputs.
	e.ctx.Set(outputs, "module", sm.definition.Name)
	sm.lastState = sm.definition.inputVars()
	e.evaluateSteps()
	return true
}

func (e *evaluator) evaluateSteps() {
	var lastContext hcl.EvalContext
	for i := 0; i < maxContextIterations; i++ {

		e.logger.Debug("Starting iteration", log.Int("iteration", i))
		e.evaluateStep()
		// Always attempt to expand any blocks that might now be expandable
		// due to new context being set.
		e.blocks = e.expandBlocks(e.blocks)

		// if ctx matches the last evaluation, we can bail, nothing left to resolve
		if i > 0 && reflect.DeepEqual(lastContext.Variables, e.ctx.Inner().Variables) {
			e.logger.Debug("Context unchanged", log.Int("iteration", i))
			break
		}
		if len(e.ctx.Inner().Variables) != len(lastContext.Variables) {
			lastContext.Variables = make(map[string]cty.Value, len(e.ctx.Inner().Variables))
		}
		for k, v := range e.ctx.Inner().Variables {
			lastContext.Variables[k] = v
		}
	}
}

func (e *evaluator) expandBlocks(blocks terraform.Blocks) terraform.Blocks {
	return e.expandDynamicBlocks(e.expandBlockForEaches(e.expandBlockCounts(blocks))...)
}

func (e *evaluator) expandDynamicBlocks(blocks ...*terraform.Block) terraform.Blocks {
	for _, b := range blocks {
		if err := b.ExpandBlock(); err != nil {
			e.logger.Debug(`Failed to expand dynamic block.`,
				log.String("block", b.FullName()), log.Err(err))
		}
	}
	return blocks
}

func isBlockSupportsForEachMetaArgument(block *terraform.Block) bool {
	return slices.Contains([]string{
		"module",
		"resource",
		"data",
	}, block.Type())
}

func (e *evaluator) expandBlockForEaches(blocks terraform.Blocks) terraform.Blocks {

	var forEachFiltered terraform.Blocks

	for _, block := range blocks {

		forEachAttr := block.GetAttribute("for_each")

		if forEachAttr.IsNil() || block.IsExpanded() || !isBlockSupportsForEachMetaArgument(block) {
			forEachFiltered = append(forEachFiltered, block)
			continue
		}

		forEachVal := forEachAttr.Value()

		if forEachVal.IsNull() || !forEachVal.IsKnown() || !forEachAttr.IsIterable() {
			e.logger.Debug(`Failed to expand block. Invalid "for-each" argument. Must be known and iterable.`,
				log.String("block", block.FullName()),
				log.String("value", forEachVal.GoString()),
			)
			continue
		}

		clones := make(map[string]cty.Value)
		_ = forEachAttr.Each(func(key cty.Value, val cty.Value) {

			if val.IsNull() {
				return
			}

			// instances are identified by a map key (or set member) from the value provided to for_each
			idx, err := convert.Convert(key, cty.String)
			if err != nil {
				e.logger.Debug(
					`Failed to expand block. Invalid "for-each" argument: map key (or set value) is not a string`,
					log.String("block", block.FullName()),
					log.String("key", key.GoString()),
					log.String("value", val.GoString()),
					log.Err(err),
				)
				return
			}

			// if the argument is a collection but not a map, then the resource identifier
			// is the value of the collection. The exception is the use of for-each inside a dynamic block,
			// because in this case the collection element may not be a primitive value.
			if (forEachVal.Type().IsCollectionType() || forEachVal.Type().IsTupleType()) &&
				!forEachVal.Type().IsMapType() {
				stringVal, err := convert.Convert(val, cty.String)
				if err != nil {
					e.logger.Debug(
						"Failed to expand block. Invalid 'for-each' argument: value is not a string",
						log.String("block", block.FullName()),
						log.String("key", idx.AsString()),
						log.String("value", val.GoString()),
						log.Err(err),
					)
					return
				}
				idx = stringVal
			}

			clone := block.Clone(idx)
			ctx := clone.Context()
			e.copyVariables(block, clone)

			eachObj := cty.ObjectVal(map[string]cty.Value{
				"key":   idx,
				"value": val,
			})

			ctx.Set(eachObj, "each")
			ctx.Set(eachObj, block.TypeLabel())
			forEachFiltered = append(forEachFiltered, clone)
			clones[idx.AsString()] = clone.Values()
		})

		metadata := block.GetMetadata()
		if len(clones) == 0 {
			e.ctx.SetByDot(cty.EmptyTupleVal, metadata.Reference())
		} else {
			// The for-each meta-argument creates multiple instances of the resource that are stored in the map.
			// So we must replace the old resource with a map with the attributes of the resource.
			e.ctx.Replace(cty.ObjectVal(clones), metadata.Reference())
		}
		e.logger.Debug("Expanded block into clones via 'for_each' attribute.",
			log.String("block", block.FullName()),
			log.Int("clones", len(clones)),
		)
	}

	return forEachFiltered
}

func isBlockSupportsCountMetaArgument(block *terraform.Block) bool {
	return slices.Contains([]string{
		"module",
		"resource",
		"data",
	}, block.Type())
}

func (e *evaluator) expandBlockCounts(blocks terraform.Blocks) terraform.Blocks {
	var countFiltered terraform.Blocks
	for _, block := range blocks {
		countAttr := block.GetAttribute("count")
		if countAttr.IsNil() || block.IsExpanded() || !isBlockSupportsCountMetaArgument(block) {
			countFiltered = append(countFiltered, block)
			continue
		}

		countAttrVal := countAttr.Value()
		if countAttrVal.IsNull() {
			// Defer to the next pass when the count might be known
			countFiltered = append(countFiltered, block)
			continue
		}

		count := 1
		if !countAttrVal.IsNull() && countAttrVal.IsKnown() && countAttrVal.Type() == cty.Number {
			count = int(countAttr.AsNumber())
		}

		var clones []cty.Value
		for i := 0; i < count; i++ {
			clone := block.Clone(cty.NumberIntVal(int64(i)))
			clones = append(clones, clone.Values())
			countFiltered = append(countFiltered, clone)
			metadata := clone.GetMetadata()
			e.ctx.SetByDot(clone.Values(), metadata.Reference())
		}
		metadata := block.GetMetadata()
		if len(clones) == 0 {
			e.ctx.SetByDot(cty.EmptyTupleVal, metadata.Reference())
		} else {
			e.ctx.SetByDot(cty.TupleVal(clones), metadata.Reference())
		}
		e.logger.Debug(
			"Expanded block into clones via 'count' attribute.",
			log.String("block", block.FullName()),
			log.Int("clones", len(clones)),
		)
	}

	return countFiltered
}

func (e *evaluator) copyVariables(from, to *terraform.Block) {

	var fromBase string
	var fromRel string
	var toRel string

	switch from.Type() {
	case "resource":
		fromBase = from.TypeLabel()
		fromRel = from.NameLabel()
		toRel = to.NameLabel()
	case "module":
		fromBase = from.Type()
		fromRel = from.TypeLabel()
		toRel = to.TypeLabel()
	default:
		return
	}

	rootCtx := e.ctx.Root()
	srcValue := rootCtx.Get(fromBase, fromRel)
	if srcValue == cty.NilVal {
		return
	}
	rootCtx.Set(srcValue, fromBase, toRel)
}

func (e *evaluator) evaluateVariable(b *terraform.Block) (cty.Value, error) {
	if b.Label() == "" {
		return cty.NilVal, errors.New("empty label - cannot resolve")
	}

	attributes := b.Attributes()
	if attributes == nil {
		return cty.NilVal, errors.New("cannot resolve variable with no attributes")
	}

	var valType cty.Type
	var defaults *typeexpr.Defaults
	if typeAttr, exists := attributes["type"]; exists {
		ty, def, err := typeAttr.DecodeVarType()
		if err != nil {
			return cty.NilVal, err
		}
		valType = ty
		defaults = def
	}

	var val cty.Value

	if override, exists := e.inputVars[b.Label()]; exists && override.Type() != cty.NilType {
		val = override
	} else if def, exists := attributes["default"]; exists {
		val = def.NullableValue()
	} else {
		return cty.NilVal, errors.New("no value found")
	}

	if valType != cty.NilType {
		if defaults != nil {
			val = defaults.Apply(val)
		}

		typedVal, err := convert.Convert(val, valType)
		if err != nil {
			return cty.NilVal, err
		}
		return typedVal, nil
	}

	return val, nil

}

func (e *evaluator) evaluateOutput(b *terraform.Block) (cty.Value, error) {
	if b.Label() == "" {
		return cty.NilVal, errors.New("empty label - cannot resolve")
	}

	attribute := b.GetAttribute("value")
	if attribute.IsNil() {
		return cty.NilVal, errors.New("cannot resolve output with no attributes")
	}
	return attribute.Value(), nil
}

// returns true if all evaluations were successful
func (e *evaluator) getValuesByBlockType(blockType string) cty.Value {

	blocksOfType := e.blocks.OfType(blockType)
	values := make(map[string]cty.Value)

	for _, b := range blocksOfType {

		switch b.Type() {
		case "variable": // variables are special in that their value comes from the "default" attribute
			val, err := e.evaluateVariable(b)
			if err != nil {
				continue
			}
			values[b.Label()] = val
		case "output":
			val, err := e.evaluateOutput(b)
			if err != nil {
				continue
			}
			values[b.Label()] = val
		case "locals", "moved", "import":
			for key, val := range b.Values().AsValueMap() {
				values[key] = val
			}
		case "provider", "module", "check":
			if b.Label() == "" {
				continue
			}
			values[b.Label()] = b.Values()
		case "data":
			if len(b.Labels()) < 2 {
				continue
			}

			blockMap, ok := values[b.Labels()[0]]
			if !ok {
				values[b.Labels()[0]] = cty.ObjectVal(make(map[string]cty.Value))
				blockMap = values[b.Labels()[0]]
			}

			valueMap := blockMap.AsValueMap()
			if valueMap == nil {
				valueMap = make(map[string]cty.Value)
			}

			valueMap[b.Labels()[1]] = b.Values()
			values[b.Labels()[0]] = cty.ObjectVal(valueMap)
		}
	}

	return cty.ObjectVal(values)
}

func (e *evaluator) getResources() map[string]cty.Value {
	values := make(map[string]map[string]cty.Value)

	for _, b := range e.blocks {
		if b.Type() != "resource" {
			continue
		}

		if len(b.Labels()) < 2 {
			continue
		}

		val, exists := values[b.Labels()[0]]
		if !exists {
			val = make(map[string]cty.Value)
			values[b.Labels()[0]] = val
		}
		val[b.Labels()[1]] = b.Values()
	}

	return lo.MapValues(values, func(v map[string]cty.Value, _ string) cty.Value {
		return cty.ObjectVal(v)
	})
}
