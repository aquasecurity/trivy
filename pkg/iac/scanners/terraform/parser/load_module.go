package parser

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser/resolvers"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	tfcontext "github.com/aquasecurity/trivy/pkg/iac/terraform/context"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// moduleConfig is a module loaded once per module call and shared by all its instances.
type moduleConfig struct {
	key      string // call path without instance keys, as in modules.json
	parser   *Parser
	children map[string]*moduleConfig // by call name
}

// loadModuleTree loads the root module and all modules below it.
func (p *Parser) loadModuleTree(ctx context.Context, workingDir string) *moduleConfig {
	root := &moduleConfig{parser: p}
	root.loadChildren(ctx, workingDir, []string{p.moduleID()})
	return root
}

// loadChildren loads the modules called by the module and their children.
// ancestors holds the IDs of the module and its parents, and a call of any of them is not loaded.
func (c *moduleConfig) loadChildren(ctx context.Context, workingDir string, ancestors []string) {
	p := c.parser
	c.children = make(map[string]*moduleConfig)
	if len(p.files) == 0 {
		return
	}

	metadata := p.loadModulesMetadata()
	evalCtx := newModuleContext(p.moduleFS, p.projectRoot, p.modulePath, workingDir, p.workspaceName)

	for _, call := range p.moduleCalls(evalCtx) {
		name := call.Label()
		if _, exists := c.children[name]; exists {
			continue
		}

		key := name
		if c.key != "" {
			key = c.key + "." + name
		}

		mp, err := p.loadModule(ctx, call, key, metadata)
		if err != nil {
			p.logger.Error("Failed to load module. Maybe try 'terraform init'?",
				log.String("loc", call.GetMetadata().Range().String()), log.Err(err))
			continue
		}

		id := mp.moduleID()
		if slices.Contains(ancestors, id) {
			p.logger.Error("Module includes itself",
				log.String("loc", call.GetMetadata().Range().String()), log.FilePath(mp.modulePath))
			continue
		}

		p.logger.Debug("Loaded module", log.String("name", name), log.FilePath(mp.modulePath))
		child := &moduleConfig{key: key, parser: mp}
		c.children[name] = child
		child.loadChildren(ctx, workingDir, append(slices.Clip(ancestors), id))
	}
}

// moduleID identifies the directory of the module and its filesystem.
func (p *Parser) moduleID() string {
	return types.CreateFSKey(p.moduleFS) + ":" + path.Clean(p.modulePath)
}

// moduleCalls returns the module blocks of the parsed files, evaluated in ctx.
// Files whose blocks cannot be read are skipped.
func (p *Parser) moduleCalls(ctx *tfcontext.Context) terraform.Blocks {
	var calls terraform.Blocks
	for _, file := range p.files {
		hclBlocks, err := loadBlocksFromFile(file)
		if err != nil {
			continue
		}
		for _, hclBlock := range hclBlocks {
			if hclBlock.Type == "module" {
				calls = append(calls, terraform.NewBlock(hclBlock, ctx, nil, nil, p.moduleSource, p.moduleFS))
			}
		}
	}
	return calls
}

// moduleCallName returns the full name of the module call with the given key, such as module.a.module.b.
func moduleCallName(key string) string {
	return "module." + strings.ReplaceAll(key, ".", ".module.")
}

// loadModule finds the source of the module call and parses the module.
func (p *Parser) loadModule(ctx context.Context, b *terraform.Block, key string, metadata *ModulesMetadata) (*Parser, error) {
	if b.Label() == "" {
		return nil, errors.New("module without label")
	}

	sourceVal := b.GetAttribute("source").Value()
	if !sourceVal.IsKnown() || sourceVal.Type() != cty.String {
		return nil, errors.New("source is not a string")
	}

	source := sourceVal.AsString()
	if source == "" {
		return nil, errors.New("source is empty")
	}

	if metadata != nil {
		// if we have module metadata we can parse all the modules as they'll be cached locally!
		mp, err := p.loadModuleFromTerraformCache(ctx, b, key, source, metadata)
		if err == nil {
			p.logger.Debug("Using module from Terraform cache .terraform/modules",
				log.String("source", source))
			return mp, nil
		}

		p.logger.Debug("Failed to load module from .terraform cache",
			log.String("module_source", source),
			log.Err(err),
		)
	}

	// we don't have the module installed via 'terraform init' so we need to grab it...
	return p.loadExternalModule(ctx, b, key, source)
}

func (p *Parser) loadModuleFromTerraformCache(ctx context.Context, b *terraform.Block, key, source string, metadata *ModulesMetadata) (*Parser, error) {
	var modulePath string
	for _, module := range metadata.Modules {
		if module.Key == key {
			modulePath = path.Clean(path.Join(p.projectRoot, module.Dir))
			break
		}
	}
	if modulePath == "" {
		return nil, fmt.Errorf("resolve module with key %q from .terraform/modules", key)
	}

	if strings.HasPrefix(source, ".") {
		source = ""
	}

	p.logger.Debug("Module resolved using modules.json",
		log.String("block", moduleCallName(key)),
		log.String("source", source),
		log.String("modulePath", modulePath),
	)
	moduleParser := p.newModuleParser(p.moduleFS, source, modulePath, b.Label())
	if err := moduleParser.ParseFS(ctx, modulePath); err != nil {
		return nil, fmt.Errorf("parse module filesystem: %w", err)
	}
	return moduleParser, nil
}

func (p *Parser) loadExternalModule(ctx context.Context, b *terraform.Block, key, source string) (*Parser, error) {

	p.logger.Debug("Locating non-initialized module", log.String("source", source))

	version := b.GetAttribute("version").AsStringValueOrDefault("", b).Value()
	opt := resolvers.Options{
		Source:          source,
		OriginalSource:  source,
		Version:         version,
		OriginalVersion: version,
		WorkingDir:      p.projectRoot,
		Name:            moduleCallName(key),
		ModulePath:      p.modulePath,
		Logger:          p.logger.With(log.Prefix("module resolver")),
		AllowDownloads:  p.allowDownloads,
		SkipCache:       p.skipCachedModules,
	}

	res, err := resolvers.Resolve(ctx, p.moduleFS, opt)
	if err != nil {
		return nil, err
	}
	prefix := path.Join(p.moduleSource, res.SourcePrefix)
	p.logger.Debug("Module resolved",
		log.String("block", moduleCallName(key)),
		log.String("source", source),
		log.String("prefix", prefix),
		log.FilePath(res.Dir),
	)
	moduleParser := p.newModuleParser(res.FS, prefix, res.Dir, b.Label())
	if err := moduleParser.ParseFS(ctx, res.Dir); err != nil {
		return nil, err
	}
	return moduleParser, nil
}
