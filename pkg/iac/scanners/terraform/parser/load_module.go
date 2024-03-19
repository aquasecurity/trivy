package parser

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/samber/lo"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser/resolvers"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

type ModuleDefinition struct {
	Name       string
	Path       string
	FileSystem fs.FS
	Definition *terraform.Block
	Parser     *Parser
	External   bool
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
			e.debug.Log("Failed to load module %q. Maybe try 'terraform init'?", err)
			continue
		}

		e.debug.Log("Loaded module %q from %q.", moduleDefinition.Name, moduleDefinition.Path)
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
		e.debug.Log("found module '%s' in .terraform/modules", source)
		return def, nil
	}

	// we don't have the module installed via 'terraform init' so we need to grab it...
	return e.loadExternalModule(ctx, b, source)
}

func (e *evaluator) loadModuleFromTerraformCache(ctx context.Context, b *terraform.Block, source string) (*ModuleDefinition, error) {
	var modulePath string
	if e.moduleMetadata != nil {
		// if we have module metadata we can parse all the modules as they'll be cached locally!
		name := b.ModuleName()
		for _, module := range e.moduleMetadata.Modules {
			if module.Key == name {
				modulePath = path.Clean(path.Join(e.projectRootPath, module.Dir))
				break
			}
		}
	}
	if modulePath == "" {
		return nil, fmt.Errorf("failed to load module from .terraform/modules")
	}
	if strings.HasPrefix(source, ".") {
		source = ""
	}

	if prefix, relativeDir, ok := strings.Cut(source, "//"); ok && !strings.HasSuffix(prefix, ":") && strings.Count(prefix, "/") == 2 {
		if !strings.HasSuffix(modulePath, relativeDir) {
			modulePath = fmt.Sprintf("%s/%s", modulePath, relativeDir)
		}
	}

	e.debug.Log("Module '%s' resolved to path '%s' in filesystem '%s' using modules.json", b.FullName(), modulePath, e.filesystem)
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

	e.debug.Log("locating non-initialized module '%s'...", source)

	version := b.GetAttribute("version").AsStringValueOrDefault("", b).Value()
	opt := resolvers.Options{
		Source:          source,
		OriginalSource:  source,
		Version:         version,
		OriginalVersion: version,
		WorkingDir:      e.projectRootPath,
		Name:            b.FullName(),
		ModulePath:      e.modulePath,
		DebugLogger:     e.debug.Extend("resolver"),
		AllowDownloads:  e.allowDownloads,
		SkipCache:       e.skipCachedModules,
	}

	filesystem, prefix, downloadPath, err := resolveModule(ctx, e.filesystem, opt)
	if err != nil {
		return nil, err
	}
	prefix = path.Join(e.parentParser.moduleSource, prefix)
	e.debug.Log("Module '%s' resolved to path '%s' in filesystem '%s' with prefix '%s'", b.FullName(), downloadPath, filesystem, prefix)
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

func sortModuleDefinitions(modules []*ModuleDefinition) ([]*ModuleDefinition, error) {
	graph := buildModuleDefinitionsGraph(modules)

	if graph.hasCycle() {
		return modules, errors.New("graph is cyclical")
	}

	sortedDefNames := graph.sort()

	defsMap := lo.SliceToMap(modules, func(definition *ModuleDefinition) (string, *ModuleDefinition) {
		return definition.Name, definition
	})

	return lo.FilterMap(sortedDefNames, func(defName string, _ int) (*ModuleDefinition, bool) {
		val, exists := defsMap[defName]
		return val, exists
	}), nil
}

type moduleDefinitionsGraph map[string][]string

func buildModuleDefinitionsGraph(modules []*ModuleDefinition) moduleDefinitionsGraph {
	graph := lo.SliceToMap(modules, func(definition *ModuleDefinition) (string, []string) {
		return definition.Name, nil
	})

	for _, def := range modules {
		for _, ref := range def.Definition.AllReferences() {
			if ref.BlockType() != terraform.TypeModule {
				continue
			}

			referencedModule := ref.TypeLabel()
			if referencedModule != "" {
				graph[def.Name] = append(graph[def.Name], referencedModule)
			}
		}
	}

	return graph
}

func (g moduleDefinitionsGraph) hasCycle() bool {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var dfs func(string) bool
	dfs = func(node string) bool {
		visited[node] = true
		recStack[node] = true

		for _, neighbor := range g[node] {
			if visited[neighbor] && recStack[neighbor] {
				return true
			}
			if !visited[neighbor] && dfs(neighbor) {
				return true
			}
		}

		recStack[node] = false
		return false
	}

	for node := range g {
		if dfs(node) {
			return true
		}
	}

	return false
}

func (g moduleDefinitionsGraph) sort() []string {
	var (
		visited = make(map[string]bool)
		stack   = make([]string, 0, len(g))
		dfs     func(n string)
	)

	dfs = func(n string) {
		if visited[n] {
			return
		}

		visited[n] = true

		for _, neighbor := range g[n] {
			dfs(neighbor)
		}

		stack = append(stack, n)
	}

	for node := range g {
		dfs(node)
	}

	return stack
}
