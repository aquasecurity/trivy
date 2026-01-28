package eval

import (
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

type LocalModuleParser struct{}

func NewParser() *LocalModuleParser {
	return &LocalModuleParser{}
}

func (p *LocalModuleParser) ParseDir(fsys fs.FS, root string) (*ModuleConfig, error) {
	rootModule, err := p.parse(fsys, root)
	if err != nil {
		return nil, err
	}
	return rootModule, nil
}

func (p *LocalModuleParser) parse(fsys fs.FS, path string) (*ModuleConfig, error) {
	hclParser := hclparse.NewParser()

	fi, err := fs.Stat(fsys, path)
	if err != nil {
		return nil, err
	}

	if fi.IsDir() {
		entries, err := fs.ReadDir(fsys, path)
		if err != nil {
			return nil, err
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if !strings.HasSuffix(entry.Name(), ".tf") {
				continue
			}
			filePath := filepath.Join(path, entry.Name())
			data, err := fs.ReadFile(fsys, filePath)
			if err != nil {
				return nil, err
			}
			if _, diags := hclParser.ParseHCL(data, filePath); diags.HasErrors() {
				return nil, diags
			}
		}
	} else {
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, err
		}
		if _, diags := hclParser.ParseHCL(data, path); diags.HasErrors() {
			return nil, diags
		}
	}

	module := &ModuleConfig{
		ModuleCalls: make(map[string]*ModuleCall),
	}

	for _, file := range hclParser.Files() {
		content, _, diags := file.Body.PartialContent(topLevelSchema)
		if diags.HasErrors() {
			return nil, diags
		}

		for _, hclBlock := range content.Blocks {
			block := parseHclBlock(hclBlock, module)
			module.Blocks = append(module.Blocks, block)
		}
	}

	for _, block := range module.Blocks {
		if block.underlying.Type == "module" {
			labels := block.underlying.Labels
			if len(labels) == 0 {
				continue
			}

			sourceAttr, exists := block.attrs["source"]
			if !exists {
				log.Printf("Skip module call without source %s", block.underlying.DefRange.String())
				continue
			}

			sourceVal, err := sourceAttr.ToValue(&hcl.EvalContext{})
			if err != nil {
				return nil, err
			}

			if !sourceVal.Type().Equals(cty.String) {
				continue
			}

			mc := &ModuleCall{
				Name:   labels[0],
				Source: sourceVal.AsString(),
				Config: block,
				FS:     fsys,
				Path:   path,
			}

			if attr, exists := block.attrs["version"]; exists {
				val, err := attr.ToValue(&hcl.EvalContext{})
				if err != nil {
					return nil, err
				}
				if val.Type().Equals(cty.String) {
					mc.Version = val.AsString()
				}
			}

			module.ModuleCalls[mc.Name] = mc
		}
	}

	return module, nil
}

func parseHclBlock(hclBlock *hcl.Block, module *ModuleConfig) *BlockConfig {
	block := BlockConfig{
		underlying: hclBlock,
		attrs:      make(map[string]*AttrConfig),
		module:     module,
	}

	switch b := hclBlock.Body.(type) {
	case *hclsyntax.Body:
		for name, hclAttr := range b.Attributes {
			block.attrs[name] = &AttrConfig{
				name:       hclAttr.Name,
				underlying: hclAttr.AsHCLAttribute(),
			}
		}
		for _, child := range b.Blocks {
			childBlock := child.AsHCLBlock()
			if childBlock.Type == "dynamic" {
				dynBlock := parseHclDynBlock(childBlock, module)
				if dynBlock != nil {
					block.dynBlocks = append(block.dynBlocks, dynBlock)
				}
			} else {
				block.children = append(block.children, parseHclBlock(childBlock, module))
			}
		}
	default:
		panic(fmt.Sprintf("unknown block's body type: %T", hclBlock.Body))
	}

	return &block
}

func parseHclDynBlock(hclBlock *hcl.Block, module *ModuleConfig) *DynBlockConfig {
	dynBlock := DynBlockConfig{
		blockType:    hclBlock.Labels[0],
		iteratorName: hclBlock.Labels[0],
	}

	// content, diags := hclBlock.Body.Content(dynBlockSchema)
	switch b := hclBlock.Body.(type) {
	case *hclsyntax.Body:
		forEachAttr, ok := b.Attributes["for_each"]
		if !ok {
			// TODO: log
			return nil
		}
		dynBlock.forEach = &AttrConfig{
			name:       forEachAttr.Name,
			underlying: forEachAttr.AsHCLAttribute(),
		}

		if hclAttr, ok := b.Attributes["iterator"]; ok {
			trav, _ := hcl.AbsTraversalForExpr(hclAttr.Expr)
			dynBlock.iteratorName = trav.RootName()
		}
		for _, child := range b.Blocks {
			if child.Type == "content" {
				childBlock := child.AsHCLBlock()
				dynBlock.content = parseHclBlock(childBlock, module)
			}
		}
		if dynBlock.content == nil {
			// TODO: log
			return nil
		}
	default:
		panic(fmt.Sprintf("unexpected dyn block's body type: %T", hclBlock.Body))
	}

	return &dynBlock
}

var topLevelSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{
			Type: "terraform",
		},
		{
			Type: "required_providers",
		},
		{
			Type:       "provider",
			LabelNames: []string{"name"},
		},
		{
			Type:       "variable",
			LabelNames: []string{"name"},
		},
		{
			Type: "locals",
		},
		{
			Type:       "output",
			LabelNames: []string{"name"},
		},
		{
			Type:       "module",
			LabelNames: []string{"name"},
		},
		{
			Type:       "check",
			LabelNames: []string{"name"},
		},
		{
			Type:       "resource",
			LabelNames: []string{"type", "name"},
		},
		{
			Type:       "data",
			LabelNames: []string{"type", "name"},
		},
		{
			Type:       "ephemeral",
			LabelNames: []string{"type", "name"},
		},
		{
			Type: "moved",
		},
		{
			Type: "import",
		},
		{
			Type: "removed",
		},
	},
}
