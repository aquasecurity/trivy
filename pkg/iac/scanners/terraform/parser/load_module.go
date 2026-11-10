package parser

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser/resolvers"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	tfcontext "github.com/aquasecurity/trivy/pkg/iac/terraform/context"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

const rootModuleName = "root"

// moduleConfig is a module loaded once per module call and shared by all its instances.
type moduleConfig struct {
	name     string // call name, "root" for the root module
	key      string // call path without instance keys, as in modules.json
	path     string // directory of the module in fsys
	fsys     fs.FS
	source   string // source prefix of metadata ranges
	files    []sourceFile
	logger   *log.Logger
	children map[string]*moduleConfig // by call name
}

// rootConfig returns the root module made of the parsed files.
func (p *Parser) rootConfig() *moduleConfig {
	return &moduleConfig{
		name:   rootModuleName,
		path:   p.modulePath,
		fsys:   p.moduleFS,
		source: p.moduleSource,
		files:  p.files,
		logger: p.logger,
	}
}

// loadModuleTree loads the root module and all modules below it.
func (p *Parser) loadModuleTree(ctx context.Context, workingDir string) *moduleConfig {
	p.modulesMetadata = make(map[string]*ModulesMetadata)
	root := p.rootConfig()
	p.loadChildren(ctx, root, workingDir, []string{root.id()})
	return root
}

// loadChildren loads the modules called by the module and their children.
// ancestors holds the IDs of the module and its parents, and a call of any of them is not loaded.
func (p *Parser) loadChildren(ctx context.Context, c *moduleConfig, workingDir string, ancestors []string) {
	c.children = make(map[string]*moduleConfig)
	if len(c.files) == 0 {
		return
	}

	metadata := p.loadModulesMetadata(c)
	evalCtx := newModuleContext(c.fsys, p.projectRoot, c.path, workingDir, p.workspaceName)

	for _, call := range c.moduleCalls(evalCtx) {
		name := call.Label()
		if _, exists := c.children[name]; exists {
			continue
		}

		key := name
		if c.key != "" {
			key = c.key + "." + name
		}

		child, err := p.loadModule(ctx, c, call, key, metadata)
		if err != nil {
			c.logger.Error("Failed to load module. Maybe try 'terraform init'?",
				log.String("loc", call.GetMetadata().Range().String()), log.Err(err))
			continue
		}

		id := child.id()
		if slices.Contains(ancestors, id) {
			c.logger.Error("Module includes itself",
				log.String("loc", call.GetMetadata().Range().String()), log.FilePath(child.path))
			continue
		}

		c.logger.Debug("Loaded module", log.String("name", name), log.FilePath(child.path))
		c.children[name] = child
		p.loadChildren(ctx, child, workingDir, append(slices.Clip(ancestors), id))
	}
}

// loadModulesMetadata reads .terraform/modules/modules.json of the project from the module filesystem,
// once per filesystem. It returns nil if the file is missing or cannot be read.
func (p *Parser) loadModulesMetadata(c *moduleConfig) *ModulesMetadata {
	fsKey := types.CreateFSKey(c.fsys)
	if metadata, loaded := p.modulesMetadata[fsKey]; loaded {
		return metadata
	}

	metadata, metadataPath, err := loadModuleMetadata(c.fsys, p.projectRoot)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		c.logger.Error("Error loading module metadata", log.Err(err))
	} else if err == nil {
		c.logger.Debug("Loaded module metadata for modules",
			log.FilePath(metadataPath),
			log.Int("count", len(metadata.Modules)),
		)
	}
	p.modulesMetadata[fsKey] = metadata
	return metadata
}

// id identifies the directory of the module and its filesystem.
func (c *moduleConfig) id() string {
	return types.CreateFSKey(c.fsys) + ":" + path.Clean(c.path)
}

// moduleCalls returns the module blocks of the parsed files, evaluated in ctx.
// Files whose blocks cannot be read are skipped.
func (c *moduleConfig) moduleCalls(ctx *tfcontext.Context) terraform.Blocks {
	var calls terraform.Blocks
	for _, file := range c.files {
		hclBlocks, err := loadBlocksFromFile(file)
		if err != nil {
			continue
		}
		for _, hclBlock := range hclBlocks {
			if hclBlock.Type == "module" {
				calls = append(calls, terraform.NewBlock(hclBlock, ctx, nil, nil, c.source, c.fsys))
			}
		}
	}
	return calls
}

// moduleCallName returns the full name of the module call with the given key, such as module.a.module.b.
func moduleCallName(key string) string {
	return "module." + strings.ReplaceAll(key, ".", ".module.")
}

// loadModule finds the source of the module call in the parent module and parses the module.
func (p *Parser) loadModule(ctx context.Context, parent *moduleConfig, b *terraform.Block, key string, metadata *ModulesMetadata) (*moduleConfig, error) {
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
		c, err := p.loadModuleFromTerraformCache(parent, b, key, source, metadata)
		if err == nil {
			parent.logger.Debug("Using module from Terraform cache .terraform/modules",
				log.String("source", source))
			return c, nil
		}

		parent.logger.Debug("Failed to load module from .terraform cache",
			log.String("module_source", source),
			log.Err(err),
		)
	}

	// we don't have the module installed via 'terraform init' so we need to grab it...
	return p.loadExternalModule(ctx, parent, b, key, source)
}

func (p *Parser) loadModuleFromTerraformCache(parent *moduleConfig, b *terraform.Block, key, source string, metadata *ModulesMetadata) (*moduleConfig, error) {
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

	parent.logger.Debug("Module resolved using modules.json",
		log.String("block", moduleCallName(key)),
		log.String("source", source),
		log.String("modulePath", modulePath),
	)
	c, err := p.parseModule(b.Label(), key, parent.fsys, source, modulePath)
	if err != nil {
		return nil, fmt.Errorf("parse module filesystem: %w", err)
	}
	return c, nil
}

func (p *Parser) loadExternalModule(ctx context.Context, parent *moduleConfig, b *terraform.Block, key, source string) (*moduleConfig, error) {

	parent.logger.Debug("Locating non-initialized module", log.String("source", source))

	version := b.GetAttribute("version").AsStringValueOrDefault("", b).Value()
	opt := resolvers.Options{
		Source:          source,
		OriginalSource:  source,
		Version:         version,
		OriginalVersion: version,
		WorkingDir:      p.projectRoot,
		Name:            moduleCallName(key),
		ModulePath:      parent.path,
		Logger:          parent.logger.With(log.Prefix("module resolver")),
		AllowDownloads:  p.allowDownloads,
		SkipCache:       p.skipCachedModules,
	}

	res, err := resolvers.Resolve(ctx, parent.fsys, opt)
	if err != nil {
		return nil, err
	}
	prefix := path.Join(parent.source, res.SourcePrefix)
	parent.logger.Debug("Module resolved",
		log.String("block", moduleCallName(key)),
		log.String("source", source),
		log.String("prefix", prefix),
		log.FilePath(res.Dir),
	)
	return p.parseModule(b.Label(), key, res.FS, prefix, res.Dir)
}

// parseModule parses the module in dir of fsys.
func (p *Parser) parseModule(name, key string, fsys fs.FS, source, dir string) (*moduleConfig, error) {
	c := &moduleConfig{
		name:   name,
		key:    key,
		path:   dir,
		fsys:   fsys,
		source: source,
		logger: p.moduleLogger(name),
	}

	files, err := p.parseDir(fsys, dir, hclparse.NewParser(), c.logger)
	if err != nil {
		return nil, err
	}
	c.files = files
	return c, nil
}
