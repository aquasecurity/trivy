package parser

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"golang.org/x/exp/slices"

	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	tfcontext "github.com/aquasecurity/trivy/pkg/iac/terraform/context"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

const (
	maxContextIterations = 32
)

type evaluator struct {
	filesystem        fs.FS
	ctx               *tfcontext.Context
	blocks            terraform.Blocks
	inputVars         map[string]cty.Value
	moduleMetadata    *modulesMetadata
	projectRootPath   string // root of the current scan
	modulePath        string
	moduleName        string
	ignores           terraform.Ignores
	parentParser      *Parser
	debug             debug.Logger
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
	ignores []terraform.Ignore,
	logger debug.Logger,
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
		debug:             logger,
		allowDownloads:    allowDownloads,
		skipCachedModules: skipCachedModules,
	}
}

func (e *evaluator) evaluateStep() {

	e.ctx.Set(e.getValuesByBlockType("variable"), "var")
	e.ctx.Set(e.getValuesByBlockType("locals"), "local")
	e.ctx.Set(e.getValuesByBlockType("provider"), "provider")

	resources := e.getValuesByBlockType("resource")
	for key, resource := range resources.AsValueMap() {
		e.ctx.Set(resource, key)
	}

	e.ctx.Set(e.getValuesByBlockType("data"), "data")
	e.ctx.Set(e.getValuesByBlockType("output"), "output")
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
		e.debug.Log("Added module output %s=%s.", block.Label(), attr.Value().GoString())
	}
	return cty.ObjectVal(data)
}

func (e *evaluator) EvaluateAll(ctx context.Context) (terraform.Modules, map[string]fs.FS, time.Duration) {

	fsKey := types.CreateFSKey(e.filesystem)
	e.debug.Log("Filesystem key is '%s'", fsKey)

	fsMap := make(map[string]fs.FS)
	fsMap[fsKey] = e.filesystem

	var parseDuration time.Duration

	var lastContext hcl.EvalContext
	start := time.Now()
	e.debug.Log("Starting module evaluation...")
	for i := 0; i < maxContextIterations; i++ {

		e.evaluateStep()

		// if ctx matches the last evaluation, we can bail, nothing left to resolve
		if i > 0 && reflect.DeepEqual(lastContext.Variables, e.ctx.Inner().Variables) {
			break
		}

		if len(e.ctx.Inner().Variables) != len(lastContext.Variables) {
			lastContext.Variables = make(map[string]cty.Value, len(e.ctx.Inner().Variables))
		}
		for k, v := range e.ctx.Inner().Variables {
			lastContext.Variables[k] = v
		}
	}

	// expand out resources and modules via count, for-each and dynamic
	// (not a typo, we do this twice so every order is processed)
	e.blocks = e.expandBlocks(e.blocks)
	e.blocks = e.expandBlocks(e.blocks)

	parseDuration += time.Since(start)

	e.debug.Log("Starting submodule evaluation...")
	var modules terraform.Modules
	for _, definition := range e.loadModules(ctx) {
		submodules, outputs, err := definition.Parser.EvaluateAll(ctx)
		if err != nil {
			e.debug.Log("Failed to evaluate submodule '%s': %s.", definition.Name, err)
			continue
		}
		// export module outputs
		e.ctx.Set(outputs, "module", definition.Name)
		modules = append(modules, submodules...)
		for key, val := range definition.Parser.GetFilesystemMap() {
			fsMap[key] = val
		}
	}
	e.debug.Log("Finished processing %d submodule(s).", len(modules))

	e.debug.Log("Starting post-submodule evaluation...")
	for i := 0; i < maxContextIterations; i++ {

		e.evaluateStep()

		// if ctx matches the last evaluation, we can bail, nothing left to resolve
		if i > 0 && reflect.DeepEqual(lastContext.Variables, e.ctx.Inner().Variables) {
			break
		}

		if len(e.ctx.Inner().Variables) != len(lastContext.Variables) {
			lastContext.Variables = make(map[string]cty.Value, len(e.ctx.Inner().Variables))
		}
		for k, v := range e.ctx.Inner().Variables {
			lastContext.Variables[k] = v
		}
	}

	e.debug.Log("Module evaluation complete.")
	parseDuration += time.Since(start)
	rootModule := terraform.NewModule(e.projectRootPath, e.modulePath, e.blocks, e.ignores)
	return append(terraform.Modules{rootModule}, modules...), fsMap, parseDuration
}

func (e *evaluator) expandBlocks(blocks terraform.Blocks) terraform.Blocks {
	return e.expandDynamicBlocks(e.expandBlockForEaches(e.expandBlockCounts(blocks), false)...)
}

func (e *evaluator) expandDynamicBlocks(blocks ...*terraform.Block) terraform.Blocks {
	for _, b := range blocks {
		e.expandDynamicBlock(b)
	}
	return blocks
}

func (e *evaluator) expandDynamicBlock(b *terraform.Block) {
	for _, sub := range b.AllBlocks() {
		e.expandDynamicBlock(sub)
	}
	for _, sub := range b.AllBlocks().OfType("dynamic") {
		if sub.IsExpanded() {
			continue
		}
		blockName := sub.TypeLabel()
		expanded := e.expandBlockForEaches(terraform.Blocks{sub}, true)
		for _, ex := range expanded {
			if content := ex.GetBlock("content"); content.IsNotNil() {
				_ = e.expandDynamicBlocks(content)
				b.InjectBlock(content, blockName)
			}
		}
		sub.MarkExpanded()
	}
}

func isBlockSupportsForEachMetaArgument(block *terraform.Block) bool {
	return slices.Contains([]string{"module", "resource", "data", "dynamic"}, block.Type())
}

func (e *evaluator) expandBlockForEaches(blocks terraform.Blocks, isDynamic bool) terraform.Blocks {
	var forEachFiltered terraform.Blocks

	for _, block := range blocks {

		forEachAttr := block.GetAttribute("for_each")

		if forEachAttr.IsNil() || block.IsExpanded() || !isBlockSupportsForEachMetaArgument(block) {
			forEachFiltered = append(forEachFiltered, block)
			continue
		}

		forEachVal := forEachAttr.Value()

		if forEachVal.IsNull() || !forEachVal.IsKnown() || !forEachAttr.IsIterable() {
			continue
		}

		clones := make(map[string]cty.Value)
		_ = forEachAttr.Each(func(key cty.Value, val cty.Value) {

			// instances are identified by a map key (or set member) from the value provided to for_each
			idx, err := convert.Convert(key, cty.String)
			if err != nil {
				e.debug.Log(
					`Invalid "for-each" argument: map key (or set value) is not a string, but %s`,
					key.Type().FriendlyName(),
				)
				return
			}

			// if the argument is a collection but not a map, then the resource identifier
			// is the value of the collection. The exception is the use of for-each inside a dynamic block,
			// because in this case the collection element may not be a primitive value.
			if (forEachVal.Type().IsCollectionType() || forEachVal.Type().IsTupleType()) &&
				!forEachVal.Type().IsMapType() && !isDynamic {
				stringVal, err := convert.Convert(val, cty.String)
				if err != nil {
					e.debug.Log("Failed to convert for-each arg %v to string", val)
					return
				}
				idx = stringVal
			}

			clone := block.Clone(idx)

			ctx := clone.Context()

			e.copyVariables(block, clone)

			ctx.SetByDot(idx, "each.key")
			ctx.SetByDot(val, "each.value")
			ctx.Set(idx, block.TypeLabel(), "key")
			ctx.Set(val, block.TypeLabel(), "value")

			forEachFiltered = append(forEachFiltered, clone)

			values := clone.Values()
			clones[idx.AsString()] = values
			e.ctx.SetByDot(values, clone.GetMetadata().Reference())
		})

		metadata := block.GetMetadata()
		if len(clones) == 0 {
			e.ctx.SetByDot(cty.EmptyTupleVal, metadata.Reference())
		} else {
			// The for-each meta-argument creates multiple instances of the resource that are stored in the map.
			// So we must replace the old resource with a map with the attributes of the resource.
			e.ctx.Replace(cty.ObjectVal(clones), metadata.Reference())
		}
		e.debug.Log("Expanded block '%s' into %d clones via 'for_each' attribute.", block.LocalName(), len(clones))
	}

	return forEachFiltered
}

func isBlockSupportsCountMetaArgument(block *terraform.Block) bool {
	return slices.Contains([]string{"module", "resource", "data"}, block.Type())
}

func (e *evaluator) expandBlockCounts(blocks terraform.Blocks) terraform.Blocks {
	var countFiltered terraform.Blocks
	for _, block := range blocks {
		countAttr := block.GetAttribute("count")
		if countAttr.IsNil() || block.IsExpanded() || !isBlockSupportsCountMetaArgument(block) {
			countFiltered = append(countFiltered, block)
			continue
		}
		count := 1
		countAttrVal := countAttr.Value()
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
		e.debug.Log("Expanded block '%s' into %d clones via 'count' attribute.", block.LocalName(), len(clones))
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

	srcValue := e.ctx.Root().Get(fromBase, fromRel)
	if srcValue == cty.NilVal {
		return
	}
	e.ctx.Root().Set(srcValue, fromBase, toRel)
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

	if override, exists := e.inputVars[b.Label()]; exists {
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
		case "resource", "data":
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
