package parser

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/defsec/parsers/terraform/parser/resolvers"

	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/zclconf/go-cty/cty"
)

type moduleLoadError struct {
	source string
	err    error
}

func (m *moduleLoadError) Error() string {
	return fmt.Sprintf("failed to load module '%s': %s", m.source, m.err)
}

type ModuleDefinition struct {
	Name       string
	Path       string
	Definition *terraform.Block
	Parser     Parser
}

// getModuleKeyName constructs the module keyname from the block label and the modulename
func (e *evaluator) getModuleKeyName(name string) (keyName string) {
	// regular expression for removing count and or for_each indexes
	indexRegExp := regexp.MustCompile(`\\[.+?\\]`)

	if e.moduleName == "root" {
		return indexRegExp.ReplaceAllString(name, "")
	}

	modules := strings.Split(e.moduleName, ":")
	for i := range modules {
		keyName += strings.TrimPrefix(modules[i], "module.")
		if i != len(modules)-1 {
			keyName += "."
		}
	}
	return indexRegExp.ReplaceAllString(keyName+"."+name, "")
}

// LoadModules reads all module blocks and loads the underlying modules, adding blocks to e.moduleBlocks
func (e *evaluator) loadModules(ctx context.Context) []*ModuleDefinition {

	blocks := e.blocks

	var moduleDefinitions []*ModuleDefinition

	expanded := e.expandBlocks(blocks.OfType("module"))

	var loadErrors []*moduleLoadError

	for _, moduleBlock := range expanded {
		if moduleBlock.Label() == "" {
			continue
		}
		moduleDefinition, err := e.loadModule(ctx, moduleBlock)
		if err != nil {
			var loadErr *moduleLoadError
			if errors.As(err, &loadErr) {
				var found bool
				for _, fm := range loadErrors {
					if fm.source == loadErr.source {
						found = true
						break
					}
				}
				if !found {
					loadErrors = append(loadErrors, loadErr)
				}
				continue
			}
			e.debug("Failed to load module '%s'. Maybe try 'terraform init'?", err)
			continue
		}
		e.debug("Loaded module '%s' from '%s'.", moduleDefinition.Name, moduleDefinition.Path)
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

	var modulePath string

	if e.moduleMetadata != nil {
		// if we have module metadata we can parse all the modules as they'll be cached locally!

		name := e.getModuleKeyName(b.Label())

		for _, module := range e.moduleMetadata.Modules {
			clean := strings.Split(name, "[")[0]
			if module.Key == clean {
				modulePath = filepath.Clean(filepath.Join(e.projectRootPath, module.Dir))
				break
			}
		}
	}
	if modulePath == "" {

		version := b.GetAttribute("version").AsStringValueOrDefault("", b).Value()
		opt := resolvers.Options{
			Source:         source,
			Version:        version,
			WorkingDir:     e.projectRootPath,
			Name:           b.FullName(),
			ModulePath:     e.modulePath,
			DebugWriter:    e.debugWriter,
			AllowDownloads: e.allowDownloads,
		}
		path, err := resolveModule(ctx, opt)
		if err != nil {
			return nil, err
		}
		e.debug("Module '%s' resolved to path '%s'", b.FullName(), path)
		modulePath = path
	}

	moduleParser := e.parentParser.NewModuleParser(modulePath, b.Label(), b)
	if err := moduleParser.ParseDirectory(modulePath); err != nil {
		return nil, err
	}

	return &ModuleDefinition{
		Name:       b.Label(),
		Path:       modulePath,
		Definition: b,
		Parser:     moduleParser,
	}, nil
}
