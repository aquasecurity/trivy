package parser

import (
	"context"
	"path"
	"sort"
	"strings"

	"github.com/samber/lo"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

// FindRootModules takes a list of module paths and identifies the root local modules.
// It builds a graph based on the module dependencies and determines the modules that have no incoming dependencies,
// considering them as root modules.
func (p *Parser) FindRootModules(ctx context.Context, dirs []string) ([]string, error) {
	for _, dir := range dirs {
		if err := p.ParseFS(ctx, dir); err != nil {
			return nil, err
		}
	}

	blocks, _, err := p.readBlocks(p.files)
	if err != nil {
		return nil, err
	}

	g := buildGraph(blocks, dirs)
	rootModules := g.rootModules()
	sort.Strings(rootModules)
	return rootModules, nil
}

type modulesGraph map[string][]string

func buildGraph(blocks terraform.Blocks, paths []string) modulesGraph {
	moduleBlocks := blocks.OfType("module")

	graph := lo.SliceToMap(paths, func(p string) (string, []string) {
		return p, nil
	})

	for _, block := range moduleBlocks {
		sourceVal := block.GetAttribute("source").Value()
		if sourceVal.Type() != cty.String {
			continue
		}

		source := sourceVal.AsString()
		if strings.HasPrefix(source, ".") {
			filename := block.GetMetadata().Range().GetFilename()
			dir := path.Dir(filename)
			graph[dir] = append(graph[dir], path.Join(dir, source))
		}
	}

	return graph
}

func (g modulesGraph) rootModules() []string {
	incomingEdges := make(map[string]int)
	for _, neighbors := range g {
		for _, neighbor := range neighbors {
			incomingEdges[neighbor]++
		}
	}

	var roots []string
	for module := range g {
		if incomingEdges[module] == 0 {
			roots = append(roots, module)
		}
	}

	return roots
}
