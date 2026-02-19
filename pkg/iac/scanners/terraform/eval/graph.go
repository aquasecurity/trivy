package eval

import (
	"fmt"
	"iter"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

type graph struct {
	logger         *log.Logger
	nodes          map[string]Node
	dependentNodes map[string]set.Set[string]

	managedResources set.Set[string]
}

func newGraph() *graph {
	return &graph{
		nodes:            make(map[string]Node),
		dependentNodes:   make(map[string]set.Set[string]),
		managedResources: set.New[string](),
	}
}

func (g *graph) build(rootModule *ModuleConfig) error {
	if err := g.buildRealNodes(rootModule); err != nil {
		return err
	}

	for _, mod := range rootModule.Children {
		if err := g.buildModuleBoundaries(mod, nil, nil); err != nil {
			return err
		}
	}

	var rootNode = &NodeRoot{}

	for _, node := range g.nodes {
		if node.Module().IsRoot() {
			g.addEdge(node, rootNode)
		}
	}
	g.addNode(rootNode)

	if err := g.linkDependencies(); err != nil {
		return err
	}
	return nil
}

func (g *graph) addNode(n Node) {
	id := n.ID()
	if _, exists := g.nodes[id]; exists {
		panic(fmt.Sprintf("node %s already exists", id))
	}
	g.nodes[id] = n
	g.dependentNodes[id] = set.New[string]()
}

func (n *graph) dependents(node Node) iter.Seq[string] {
	return n.dependentNodes[node.ID()].Iter()
}

func (g *graph) addEdge(dependency, dependent Node) {
	g.addDependent(dependency, dependent)
}

func (n *graph) addDependent(src, target Node) {
	if n.dependentNodes[src.ID()] == nil {
		n.dependentNodes[src.ID()] = set.New[string]()
	}
	n.dependentNodes[src.ID()].Append(target.ID())
}

// findCycle detects a dependency cycle in the graph.
// Returns a slice of node IDs forming the cycle, or nil if none exists.
//
// The result is deterministic: nodes and their dependencies are
// traversed in sorted order, so repeated calls will produce the same cycle.
func (g *graph) findCycle() []string {
	const (
		white = 0
		gray  = 1
		black = 2
	)

	color := map[string]int{}
	parent := map[string]string{}

	var dfs func(string) []string
	dfs = func(v string) []string {
		color[v] = gray

		n := g.nodes[v]
		deps := make([]string, 0, g.dependentNodes[v].Size())
		for dep := range g.dependents(n) {
			deps = append(deps, dep)
		}
		sort.Strings(deps)

		for _, dep := range deps {
			switch color[dep] {
			case white:
				parent[dep] = v
				if c := dfs(dep); c != nil {
					return c
				}
			case gray:
				cycle := []string{dep}
				for x := v; x != dep; x = parent[x] {
					cycle = append(cycle, x)
				}
				cycle = append(cycle, dep)
				slices.Reverse(cycle)
				return cycle
			}
		}

		color[v] = black
		return nil
	}

	keys := make([]string, 0, len(g.nodes))
	for id := range g.nodes {
		keys = append(keys, id)
	}
	sort.Strings(keys)

	for _, id := range keys {
		if color[id] == white {
			if c := dfs(id); c != nil {
				return c
			}
		}
	}
	return nil
}

// TopoSort performs a topological sort of the graph nodes.
// Returns the sorted nodes, or an error if a dependency cycle is detected.
func (g *graph) TopoSort() ([]Node, error) {
	if cycle := g.findCycle(); len(cycle) > 0 {
		return nil, fmt.Errorf(
			"dependency cycle detected: %s",
			strings.Join(cycle, " -> "),
		)
	}

	inDegree := make(map[string]int)
	keys := make([]string, 0, len(g.nodes))
	for id := range g.nodes {
		inDegree[id] = 0
		keys = append(keys, id)
	}

	sort.Strings(keys)

	for _, id := range keys {
		n := g.nodes[id]
		for dep := range g.dependents(n) {
			inDegree[dep]++
		}
	}

	queue := make([]Node, 0, len(g.nodes))
	for _, id := range keys {
		if inDegree[id] == 0 {
			queue = append(queue, g.nodes[id])
		}
	}

	result := make([]Node, 0, len(g.nodes))

	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		result = append(result, n)

		depKeys := make([]string, 0, g.dependentNodes[n.ID()].Size())
		for dep := range g.dependents(n) {
			depKeys = append(depKeys, dep)
		}
		sort.Strings(depKeys)

		for _, dep := range depKeys {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, g.nodes[dep])
			}
		}
	}
	return result, nil
}

func nodeIDs(nodes []Node) []string {
	ids := make([]string, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID()
	}
	return ids
}

func (g *graph) buildRealNodes(module *ModuleConfig) error {
	moduleAddr := module.AbsAddr()
	for _, block := range module.Blocks {
		switch blockType := block.underlying.Type; blockType {
		case "locals":
			for _, attr := range block.attrs {
				nodeId := moduleAddr.BlockAddr(LocalAddr{Name: attr.name})
				g.addNode(&NodeLocal{
					BaseNode:            newBaseNode(nodeId, moduleAddr),
					AttributeReferencer: AttributeReferencer{Attr: attr},
					Name:                attr.name,
				})
			}
		case "output":
			name := block.underlying.Labels[0]
			nodeId := moduleAddr.BlockAddr(OutputAddr{Name: name})
			g.addNode(&NodeOutput{
				BaseNode:            newBaseNode(nodeId, moduleAddr),
				AttributeReferencer: AttributeReferencer{Attr: block.attrs["value"]},
				Name:                name,
			})
		case "variable":
			name := block.underlying.Labels[0]
			nodeId := moduleAddr.BlockAddr(VariableAddr{Name: name})
			if module.IsRoot() {
				g.addNode(&NodeRootVariable{
					BaseNode: newBaseNode(nodeId, moduleAddr),
					Name:     name,
					Default:  block.attrs["default"],
					Type:     block.attrs["type"],
				})
			} else {
				g.addNode(&NodeVariable{
					BaseNode:            newBaseNode(nodeId, moduleAddr),
					AttributeReferencer: AttributeReferencer{Attr: module.Config.attrs[name]},
					Name:                name,
					Default:             block.attrs["default"],
					Type:                block.attrs["type"],
				})
			}
		case "resource", "data":
			typ := block.underlying.Labels[0]
			name := block.underlying.Labels[1]
			addr := ResourceAddr{Mode: modeByBlockType(blockType), Type: typ, Name: name}
			absAddr := module.AbsAddr().BlockAddr(addr)
			g.addNode(&ResourceNode{
				BaseNode: newBaseNode(absAddr, module.AbsAddr()),
				Block:    block,
				Type:     typ,
				Name:     name,
				Addr:     addr,
			})

			if blockType == "resource" {
				g.managedResources.Append(typ)
			}
		}
	}

	for _, childModule := range module.Children {
		if err := g.buildRealNodes(childModule); err != nil {
			return err
		}
	}

	return nil
}

func (g *graph) buildModuleBoundaries(module *ModuleConfig, parentCall, parentExit Node) error {
	moduleAddr := module.AbsAddr()
	moduleCallNode := &NodeModuleCall{
		BaseNode: newBaseNode(moduleAddr, moduleAddr.Parent()),
		Block:    module.Config,
		Name:     module.Name,
		Call:     module.ModuleCalls[module.Name],
	}
	moduleExitNode := &NodeModuleExit{
		BaseNode: newBaseNode(moduleAddr, moduleAddr.Parent()),
	}

	g.addNode(moduleCallNode)
	g.addNode(moduleExitNode)

	for _, node := range g.nodes {
		if node.Module().Equal(moduleAddr) {
			g.addEdge(moduleCallNode, node)
			g.addEdge(node, moduleExitNode)
		}
	}

	g.addEdge(moduleCallNode, moduleExitNode)
	if parentCall != nil {
		g.addEdge(parentCall, moduleCallNode)
	}
	if parentExit != nil {
		g.addEdge(moduleExitNode, parentExit)
	}

	for _, childModule := range module.Children {
		if err := g.buildModuleBoundaries(childModule, moduleCallNode, moduleExitNode); err != nil {
			return err
		}
	}
	return nil
}

func (g *graph) linkDependencies() error {
	logger := log.WithPrefix("graph")
	for _, node := range g.nodes {
		referencer, ok := node.(Referencer)
		if !ok {
			continue
		}

		module := node.Module()
		for _, ref := range referencer.References() {
			switch addr := ref.Addr.(type) {
			case ForEachAddr, CountAddr:
				continue
			case ResourceAddr:
				// reference to a non-existent resource
				if addr.Mode == ManagedMode && !g.managedResources.Contains(addr.Type) {
					continue
				}
			}
			var depNodeAddr Address
			switch node.(type) {
			case *NodeVariable:
				// The variable node depends on the node from the parent module.
				depNodeAddr = module.Parent().BlockAddr(ref.Addr)
			default:
				depNodeAddr = module.BlockAddr(ref.Addr)
			}

			depNode, exists := g.nodes[depNodeAddr.Key()]
			if !exists {
				logger.Debug("Dependency node not found for node",
					log.String("dependency", ref.Addr.Key()), log.String("dependent", node.ID()))
				continue
			}
			g.addEdge(depNode, node)
		}
	}

	return nil
}

func (g *graph) String() string {
	var sb strings.Builder
	sb.WriteString("digraph G {\n")
	for _, node := range g.nodes {
		for dep := range g.dependents(node) {
			depNode := g.nodes[dep]
			sb.WriteString("  ")
			sb.WriteString(strconv.Quote(depNode.ID()))
			sb.WriteString(" -> ")
			sb.WriteString(strconv.Quote(node.ID()))
			sb.WriteString(";\n")
		}
	}

	sb.WriteString("}")
	return sb.String()
}
