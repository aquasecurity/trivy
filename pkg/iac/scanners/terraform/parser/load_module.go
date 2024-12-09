package parser

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser/resolvers"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/log"
)

type ModuleDefinition struct {
	Name       string
	Path       string
	FileSystem fs.FS
	Definition *terraform.Block
	Parser     *Parser
	External   bool
}

func (d *ModuleDefinition) inputVars() map[string]cty.Value {
	inputs := d.Definition.Values().AsValueMap()
	if inputs == nil {
		return make(map[string]cty.Value)
	}
	return inputs
}

// loadModules reads all module blocks and loads them
func (e *evaluator) loadModules(ctx context.Context) []*ModuleDefinition {
	var moduleDefinitions []*ModuleDefinition

	expanded := e.expandBlocks(e.blocks.OfType("module"))

	for _, moduleBlock := range expanded {
		if moduleBlock.Label() == "" {
			continue
		}
		moduleDefinition, err := e.loadModule(ctx, moduleBlock)
		if err != nil {
			e.logger.Error("Failed to load module. Maybe try 'terraform init'?", log.Err(err))
			continue
		}

		e.logger.Debug("Loaded module", log.String("name", moduleDefinition.Name), log.FilePath(moduleDefinition.Path))
		moduleDefinitions = append(moduleDefinitions, moduleDefinition)
	}

	return moduleDefinitions
}

// takes in a module "x" {} block and loads resources etc. into e.moduleBlocks - additionally returns variables to add to ["module.x.*"] variables
func (e *evaluator) loadModule(ctx context.Context, b *terraform.Block) (*ModuleDefinition, error) {

	metadata := b.GetMetadata()

	if b.Label() == "" {
		return nil, fmt.Errorf("module without label at %s", metadata.Range())
	}

	var source string
	attrs := b.Attributes()
	for _, attr := range attrs {
		if attr.Name() == "source" {
			sourceVal := attr.Value()
			if sourceVal.Type() == cty.String {
				source = sourceVal.AsString()
			}
		}
	}
	if source == "" {
		return nil, fmt.Errorf("could not read module source attribute at %s", metadata.Range().String())
	}

	if def, err := e.loadModuleFromTerraformCache(ctx, b, source); err == nil {
		e.logger.Debug("Using module from Terraform cache .terraform/modules", log.String("source", source))
		return def, nil
	}

	// we don't have the module installed via 'terraform init' so we need to grab it...
	return e.loadExternalModule(ctx, b, source)
}

func (e *evaluator) loadModuleFromTerraformCache(ctx context.Context, b *terraform.Block, source string) (*ModuleDefinition, error) {
	var modulePath string
	if e.moduleMetadata != nil {
		// if we have module metadata we can parse all the modules as they'll be cached locally!
		moduleKey := b.ModuleKey()
		for _, module := range e.moduleMetadata.Modules {
			if module.Key == moduleKey {
				modulePath = path.Clean(path.Join(e.projectRootPath, module.Dir))
				break
			}
		}
	}
	if modulePath == "" {
		return nil, errors.New("failed to load module from .terraform/modules")
	}
	if strings.HasPrefix(source, ".") {
		source = ""
	}

	if prefix, relativeDir, ok := strings.Cut(source, "//"); ok && !strings.HasSuffix(prefix, ":") && strings.Count(prefix, "/") == 2 {
		if !strings.HasSuffix(modulePath, relativeDir) {
			modulePath = fmt.Sprintf("%s/%s", modulePath, relativeDir)
		}
	}

	e.logger.Debug("Module resolved using modules.json",
		log.String("block", b.FullName()),
		log.String("source", source),
		log.String("modulePath", modulePath),
	)
	moduleParser := e.parentParser.newModuleParser(e.filesystem, source, modulePath, b.Label(), b)
	if err := moduleParser.ParseFS(ctx, modulePath); err != nil {
		return nil, err
	}
	return &ModuleDefinition{
		Name:       b.Label(),
		Path:       modulePath,
		Definition: b,
		Parser:     moduleParser,
		FileSystem: e.filesystem,
	}, nil
}

func (e *evaluator) loadExternalModule(ctx context.Context, b *terraform.Block, source string) (*ModuleDefinition, error) {

	e.logger.Debug("Locating non-initialized module", log.String("source", source))

	version := b.GetAttribute("version").AsStringValueOrDefault("", b).Value()
	opt := resolvers.Options{
		Source:          source,
		OriginalSource:  source,
		Version:         version,
		OriginalVersion: version,
		WorkingDir:      e.projectRootPath,
		Name:            b.FullName(),
		ModulePath:      e.modulePath,
		Logger:          log.WithPrefix("module resolver"),
		AllowDownloads:  e.allowDownloads,
		SkipCache:       e.skipCachedModules,
	}

	filesystem, prefix, downloadPath, err := resolveModule(ctx, e.filesystem, opt)
	if err != nil {
		return nil, err
	}
	prefix = path.Join(e.parentParser.moduleSource, prefix)
	e.logger.Debug("Module resolved",
		log.String("block", b.FullName()),
		log.String("source", source),
		log.String("prefix", prefix),
		log.FilePath(downloadPath),
	)
	moduleParser := e.parentParser.newModuleParser(filesystem, prefix, downloadPath, b.Label(), b)
	if err := moduleParser.ParseFS(ctx, downloadPath); err != nil {
		return nil, err
	}
	return &ModuleDefinition{
		Name:       b.Label(),
		Path:       downloadPath,
		Definition: b,
		Parser:     moduleParser,
		FileSystem: filesystem,
		External:   true,
	}, nil
}
