package eval

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/log"
)

type parserOpts struct {
	StopOnHCLError bool
	SkipPaths      []string
}

type moduleParser struct {
	logger    *log.Logger
	opts      parserOpts
	hclParser *hclparse.Parser
}

func newModuleParser(logger *log.Logger, opts parserOpts) *moduleParser {
	return &moduleParser{
		logger:    logger,
		opts:      opts,
		hclParser: hclparse.NewParser(),
	}
}

func (p *moduleParser) parseDir(fsys fs.FS, modulePath string) (*ModuleConfig, error) {
	module := &ModuleConfig{
		Path: modulePath,
		FS:   fsys,

		ModuleCalls: make(map[string]*ModuleCall),
	}

	if err := p.parseModuleFiles(fsys, modulePath); err != nil {
		return nil, fmt.Errorf("parse files: %w", err)
	}

	for _, file := range p.hclParser.Files() {
		content, _, diags := file.Body.PartialContent(fileBodySchema)
		if diags.HasErrors() {
			p.logger.Error("Failed to get file body content")
			continue
		}

		for _, hclBlock := range content.Blocks {
			module.Blocks = append(module.Blocks, parseHclBlock(hclBlock, module))
		}
	}

	for _, block := range module.Blocks {
		if block.underlying.Type == "module" {
			labels := block.underlying.Labels
			if len(labels) == 0 {
				continue
			}

			mc, err := parseModuleCall(block)
			if err != nil {
				p.logger.Debug("Failed to parse module call", log.String("name", labels[0]))
				continue
			}
			mc.FS = fsys
			mc.Path = modulePath
			module.ModuleCalls[mc.Name] = mc
		}
	}

	return module, nil
}

func (p *moduleParser) parseModuleFiles(fsys fs.FS, modulePath string) error {
	fi, err := fs.Stat(fsys, modulePath)
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}

	if !fi.IsDir() {
		p.logger.Debug("Module path is not a directory, skipping")
		return nil
	}

	entries, err := fs.ReadDir(fsys, modulePath)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !(strings.HasSuffix(name, ".tf") || strings.HasSuffix(name, ".tofu") ||
			strings.HasSuffix(name, ".tf.json") || strings.HasSuffix(name, ".tofu.json")) {
			continue
		}
		filePath := path.Join(modulePath, name)

		if utils.SkipPath(filePath, utils.CleanSkipPaths(p.opts.SkipPaths)) {
			p.logger.Debug("Skipping path based on input glob",
				log.FilePath(filePath), log.Any("glob", p.opts.SkipPaths))
			continue
		}

		if err := p.parseFile(fsys, filePath); err != nil {
			return fmt.Errorf("parse HCL file: %w", err)
		}
	}

	return nil
}

func (p *moduleParser) parseFile(fsys fs.FS, filePath string) error {
	data, err := fs.ReadFile(fsys, filePath)
	if err != nil {
		return err
	}

	var parseFunc = p.hclParser.ParseHCL
	if path.Ext(filePath) == ".json" {
		parseFunc = p.hclParser.ParseJSON
	}

	_, diags := parseFunc(data, filePath)
	if diags.HasErrors() && p.opts.StopOnHCLError {
		return diags
	}

	errc := p.showParseErrors(fsys, filePath, diags)
	if errc == nil {
		return nil
	}
	p.logger.Error("Failed to get the causes of the parsing error", log.Err(errc))
	p.logger.Error("Failed to parse HCL file", log.FilePath(filePath), log.Err(err))
	return nil
}

func (p *moduleParser) showParseErrors(fsys fs.FS, filePath string, diags hcl.Diagnostics) error {
	file, err := fsys.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	defer file.Close()

	for _, diag := range diags {
		if subj := diag.Subject; subj != nil {
			lines, err := readLinesFromFile(file, subj.Start.Line, subj.End.Line)
			if err != nil {
				return err
			}

			cause := strings.Join(lines, "\n")
			p.logger.Error("Error parsing file", log.FilePath(filePath),
				log.String("cause", cause), log.Err(diag))
		}
	}

	return nil
}

func readLinesFromFile(f io.Reader, from, to int) ([]string, error) {
	scanner := bufio.NewScanner(f)
	rawLines := make([]string, 0, to-from+1)

	for lineNum := 0; scanner.Scan() && lineNum < to; lineNum++ {
		if lineNum >= from-1 {
			rawLines = append(rawLines, scanner.Text())
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan file: %w", err)
	}

	return rawLines, nil
}

func parseModuleCall(block *BlockConfig) (*ModuleCall, error) {
	source, err := resolveModuleSoruce(block.attrs["source"])
	if err != nil {
		return nil, fmt.Errorf("resolve source: %w", err)
	}

	ver, err := resolveModuleVersion(block.attrs["version"])
	if err != nil {
		return nil, fmt.Errorf("resolve version: %w", err)
	}

	mc := &ModuleCall{
		Name:    block.underlying.Labels[0],
		Source:  source,
		Version: ver,
		Config:  block,
	}
	return mc, nil
}

func resolveModuleSoruce(attr *AttrConfig) (string, error) {
	if attr == nil {
		// Source is a required attribute
		return "", errors.New("source is missing")
	}

	// TODO: It might be simple to check if the expression is hclsyntx.LiteralExpression.
	val, err := attr.underlying.Expr.Value(&hcl.EvalContext{})
	if err != nil {
		return "", fmt.Errorf("eval: %w", err)
	}

	if !val.Type().Equals(cty.String) {
		return "", fmt.Errorf("expected string, but got: %s", val.GoString())
	}

	return val.AsString(), nil
}

func resolveModuleVersion(attr *AttrConfig) (string, error) {
	if attr == nil {
		// Version is an optional attribute
		return "", nil
	}

	// TODO: It might be simple to check if the expression is hclsyntx.LiteralExpression.
	val, err := attr.ToValue(&hcl.EvalContext{})
	if err != nil {
		return "", fmt.Errorf("eval: %w", err)
	}

	if !val.Type().Equals(cty.String) {
		return "", fmt.Errorf("expected string, but got: %s", val.GoString())
	}

	return val.AsString(), nil
}

func parseHclBlock(hclBlock *hcl.Block, module *ModuleConfig) *BlockConfig {
	block := BlockConfig{
		underlying: hclBlock,
		attrs:      make(map[string]*AttrConfig),
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
		attrs, diags := b.JustAttributes()
		if !diags.HasErrors() {
			for _, attr := range attrs {
				block.attrs[attr.Name] = &AttrConfig{
					name:       attr.Name,
					underlying: attr,
				}
			}
		}
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

var fileBodySchema = &hcl.BodySchema{
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
