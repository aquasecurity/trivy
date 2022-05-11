package parser

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"time"

	"github.com/aquasecurity/defsec/internal/types"

	tfcontext "github.com/aquasecurity/defsec/pkg/scanners/terraform/context"
	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

const (
	maxContextIterations = 32
)

type evaluator struct {
	filesystem      fs.FS
	ctx             *tfcontext.Context
	blocks          terraform.Blocks
	inputVars       map[string]cty.Value
	moduleMetadata  *modulesMetadata
	projectRootPath string // root of the current scan
	modulePath      string
	moduleName      string
	ignores         terraform.Ignores
	parentParser    *Parser
	debugWriter     io.Writer
	allowDownloads  bool
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
	debugWriter io.Writer,
	allowDownloads bool,
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
		filesystem:      target,
		parentParser:    parentParser,
		modulePath:      modulePath,
		moduleName:      moduleName,
		projectRootPath: projectRootPath,
		ctx:             ctx,
		blocks:          blocks,
		inputVars:       inputVars,
		moduleMetadata:  moduleMetadata,
		ignores:         ignores,
		debugWriter:     debugWriter,
		allowDownloads:  allowDownloads,
	}
}

func (e *evaluator) debug(format string, args ...interface{}) {
	if e.debugWriter == nil {
		return
	}
	prefix := fmt.Sprintf("[debug:eval][%s] ", e.moduleName)
	_, _ = e.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
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
		e.debug("Added module output %s=%s.", block.Label(), attr.Value().GoString())
	}
	return cty.ObjectVal(data)
}

func (e *evaluator) EvaluateAll(ctx context.Context) (terraform.Modules, map[string]fs.FS, time.Duration) {

	fsMap := make(map[string]fs.FS)
	fsMap[types.CreateFSKey(e.filesystem)] = e.filesystem

	var parseDuration time.Duration

	var lastContext hcl.EvalContext
	start := time.Now()
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

	// expand out resources and modules via count (not a typo, we do this twice so every order is processed)
	e.blocks = e.expandBlocks(e.blocks)
	e.blocks = e.expandBlocks(e.blocks)

	parseDuration += time.Since(start)

	var modules []*terraform.Module
	for _, definition := range e.loadModules(ctx) {
		submodules, outputs, err := definition.Parser.EvaluateAll(ctx)
		if err != nil {
			e.debug("Failed to evaluate submodule '%s': %s.", definition.Name, err)
			continue
		}
		// export module outputs
		e.ctx.Set(outputs, "module", definition.Name)
		modules = append(modules, submodules...)
		for key, val := range definition.Parser.GetFilesystemMap() {
			fsMap[key] = val
		}
	}
	e.debug("Finished processing %d submodule(s).", len(modules))

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

	parseDuration += time.Since(start)
	return append([]*terraform.Module{terraform.NewModule(e.projectRootPath, e.modulePath, e.blocks, e.ignores)}, modules...), fsMap, parseDuration
}

func (e *evaluator) expandBlocks(blocks terraform.Blocks) terraform.Blocks {
	return e.expandDynamicBlocks(e.expandBlockForEaches(e.expandBlockCounts(blocks))...)
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
		blockName := sub.TypeLabel()
		expanded := e.expandBlockForEaches(terraform.Blocks{sub})
		for _, ex := range expanded {
			if content := ex.GetBlock("content"); content.IsNotNil() {
				_ = e.expandDynamicBlocks(content)
				b.InjectBlock(content, blockName)
			}
		}
	}
}

func (e *evaluator) expandBlockForEaches(blocks terraform.Blocks) terraform.Blocks {
	var forEachFiltered terraform.Blocks

	for _, block := range blocks {

		forEachAttr := block.GetAttribute("for_each")

		if forEachAttr.IsNil() || block.IsCountExpanded() || (block.Type() != "resource" && block.Type() != "module" && block.Type() != "dynamic") {
			forEachFiltered = append(forEachFiltered, block)
			continue
		}
		if !forEachAttr.Value().IsNull() && forEachAttr.Value().IsKnown() && forEachAttr.IsIterable() {
			var clones []cty.Value
			_ = forEachAttr.Each(func(key cty.Value, val cty.Value) {

				index := key

				switch val.Type() {
				case cty.String, cty.Number:
					index = val
				}

				clone := block.Clone(index)

				ctx := clone.Context()

				e.copyVariables(block, clone)

				ctx.SetByDot(key, "each.key")
				ctx.SetByDot(val, "each.value")

				ctx.Set(key, block.TypeLabel(), "key")
				ctx.Set(val, block.TypeLabel(), "value")

				forEachFiltered = append(forEachFiltered, clone)

				clones = append(clones, clone.Values())
				metadata := clone.GetMetadata()
				e.ctx.SetByDot(clone.Values(), metadata.Reference().String())
			})
			metadata := block.GetMetadata()
			if len(clones) == 0 {
				e.ctx.SetByDot(cty.EmptyTupleVal, metadata.Reference().String())
			} else {
				e.ctx.SetByDot(cty.TupleVal(clones), metadata.Reference().String())
			}
			e.debug("Expanded block '%s' into %d clones via 'for_each' attribute.", block.LocalName(), len(clones))
		}
	}

	return forEachFiltered
}

func (e *evaluator) expandBlockCounts(blocks terraform.Blocks) terraform.Blocks {
	var countFiltered terraform.Blocks
	for _, block := range blocks {
		countAttr := block.GetAttribute("count")
		if countAttr.IsNil() || block.IsCountExpanded() || (block.Type() != "resource" && block.Type() != "module") {
			countFiltered = append(countFiltered, block)
			continue
		}
		count := 1
		if !countAttr.Value().IsNull() && countAttr.Value().IsKnown() {
			if countAttr.Value().Type() == cty.Number {
				f, _ := countAttr.Value().AsBigFloat().Float64()
				count = int(f)
			}
		}

		var clones []cty.Value
		for i := 0; i < count; i++ {
			c, _ := gocty.ToCtyValue(i, cty.Number)
			clone := block.Clone(c)
			clones = append(clones, clone.Values())
			block.TypeLabel()
			countFiltered = append(countFiltered, clone)
			metadata := clone.GetMetadata()
			e.ctx.SetByDot(clone.Values(), metadata.Reference().String())
		}
		metadata := block.GetMetadata()
		if len(clones) == 0 {
			e.ctx.SetByDot(cty.EmptyTupleVal, metadata.Reference().String())
		} else {
			e.ctx.SetByDot(cty.TupleVal(clones), metadata.Reference().String())
		}
		e.debug("Expanded block '%s' into %d clones via 'count' attribute.", block.LocalName(), len(clones))
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
		return cty.NilVal, fmt.Errorf("empty label - cannot resolve")
	}
	if override, exists := e.inputVars[b.Label()]; exists {
		return override, nil
	}
	attributes := b.Attributes()
	if attributes == nil {
		return cty.NilVal, fmt.Errorf("cannot resolve variable with no attributes")
	}
	if def, exists := attributes["default"]; exists {
		return def.Value(), nil
	}
	return cty.NilVal, fmt.Errorf("no value found")
}

func (e *evaluator) evaluateOutput(b *terraform.Block) (cty.Value, error) {
	if b.Label() == "" {
		return cty.NilVal, fmt.Errorf("empty label - cannot resolve")
	}

	attribute := b.GetAttribute("value")
	if attribute.IsNil() {
		return cty.NilVal, fmt.Errorf("cannot resolve variable with no attributes")
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
		case "locals", "moved":
			for key, val := range b.Values().AsValueMap() {
				values[key] = val
			}
		case "provider", "module":
			if b.Label() == "" {
				continue
			}
			values[b.Label()] = b.Values()
		case "resource", "data":
			if len(b.Labels()) < 2 {
				continue
			}

			blockMap, ok := values[b.Label()]
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
