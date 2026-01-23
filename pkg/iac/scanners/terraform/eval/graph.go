package eval

import (
	"errors"
	"fmt"
	"iter"
	"maps"
	"strconv"
	"strings"
)

type graph struct {
	nodes        map[string]Node
	dependents   map[string]map[string]struct{}
	dependencies map[string]map[string]struct{}

	managedResources map[string]struct{}
}

func NewGraph() *graph {
	return &graph{
		nodes:            make(map[string]Node),
		dependents:       make(map[string]map[string]struct{}),
		dependencies:     make(map[string]map[string]struct{}),
		managedResources: make(map[string]struct{}),
	}
}

func (g *graph) Populate(rootModule *ModuleConfig) error {
	if err := buildRealNodes(g, rootModule); err != nil {
		return err
	}

	for _, mod := range rootModule.Children {
		if err := buildModuleNodes(g, mod, nil, nil); err != nil {
			return err
		}
	}

	rootNode := &NodeRoot{rootModule.AbsAddr()}
	for _, node := range g.nodes {
		if node.Module().IsRoot() {
			g.AddEdge(node, rootNode)
		}
	}
	g.AddNode(rootNode)

	if err := buildEdges(g); err != nil {
		return err
	}
	return nil
}

func (g *graph) AddNode(n Node) {
	id := n.ID()
	if _, exists := g.nodes[id]; exists {
		panic(fmt.Sprintf("node %s already exists", id))
	}
	g.nodes[id] = n
}

func (n *graph) Dependents(node Node) iter.Seq[string] {
	return maps.Keys(n.dependents[node.ID()])
}

func (n *graph) Dependencies(node Node) iter.Seq[string] {
	return maps.Keys(n.dependencies[node.ID()])
}

func (n *graph) AddDependent(src, target Node) {
	if n.dependents[src.ID()] == nil {
		n.dependents[src.ID()] = make(map[string]struct{})
	}
	n.dependents[src.ID()][target.ID()] = struct{}{}
}

func (n *graph) AddDependency(src, target Node) {
	if n.dependencies[src.ID()] == nil {
		n.dependencies[src.ID()] = make(map[string]struct{})
	}
	n.dependencies[src.ID()][target.ID()] = struct{}{}
}
func (g *graph) AddEdge(dependency, dependent Node) {
	g.AddDependent(dependency, dependent)
	g.AddDependency(dependent, dependency)
}

func (g *graph) TopoSort() ([]Node, error) {
	inDegree := make(map[string]int)
	for id := range g.nodes {
		inDegree[id] = 0
	}

	for _, n := range g.nodes {
		for dep := range g.Dependents(n) {
			inDegree[dep]++
		}
	}

	queue := make([]Node, 0)
	for id, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, g.nodes[id])
		}
	}

	result := make([]Node, 0, len(g.nodes))

	for len(queue) > 0 {
		n := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		result = append(result, n)
		for dep := range g.Dependents(n) {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, g.nodes[dep])
			}
		}
	}

	if len(result) != len(g.nodes) {
		return nil, errors.New("cycle detected in graph")
	}
	return result, nil
}

func buildRealNodes(g *graph, module *ModuleConfig) error {
	moduleAddr := module.AbsAddr()
	for _, block := range module.Blocks {
		switch blockType := block.underlying.Type; blockType {
		case "locals":
			for _, attr := range block.attrs {
				nodeId := moduleAddr.BlockAddr(LocalAddr{Name: attr.name})
				g.AddNode(&NodeLocal{
					BaseNode:            newBaseNode(nodeId, moduleAddr),
					AttributeReferencer: &AttributeReferencer{Attr: attr},
					Name:                attr.name,
				})
			}
		case "output":
			name := block.underlying.Labels[0]
			nodeId := moduleAddr.BlockAddr(OutputAddr{Name: name})
			g.AddNode(&NodeOutput{
				BaseNode:            newBaseNode(nodeId, moduleAddr),
				AttributeReferencer: &AttributeReferencer{Attr: block.attrs["value"]},
				Name:                name,
			})
		case "variable":
			name := block.underlying.Labels[0]
			nodeId := moduleAddr.BlockAddr(VariableAddr{Name: name})
			if module.IsRoot() {
				g.AddNode(&NodeRootVariable{
					BaseNode: newBaseNode(nodeId, moduleAddr),
					Name:     name,
					Default:  block.attrs["default"],
					Type:     block.attrs["type"],
				})
			} else {
				g.AddNode(&NodeVariable{
					BaseNode:            newBaseNode(nodeId, moduleAddr),
					AttributeReferencer: &AttributeReferencer{Attr: module.Block.attrs[name]},
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
			g.AddNode(&ResourceNode{
				BaseNode: newBaseNode(absAddr, module.AbsAddr()),
				Block:    block,
				Type:     typ,
				Name:     name,
				Addr:     addr,
			})

			if blockType == "resource" {
				g.managedResources[typ] = struct{}{}
			}
		}
	}

	for _, childModule := range module.Children {
		if err := buildRealNodes(g, childModule); err != nil {
			return err
		}
	}

	return nil
}

func buildModuleNodes(g *graph, module *ModuleConfig, parentCall, parentExit Node) error {
	moduleAddr := module.AbsAddr()
	moduleCallNode := &NodeModuleCall{
		BaseNode: newBaseNode(moduleAddr, moduleAddr.Parent()),
		Block:    module.Block,
		Name:     module.Name,
		Call:     module.ModuleCalls[module.Name],
	}
	moduleExitNode := &NodeModuleExit{
		BaseNode: newBaseNode(moduleAddr, moduleAddr.Parent()),
	}

	for _, node := range g.nodes {
		if node.Module().Equal(moduleAddr) {
			g.AddEdge(moduleCallNode, node)
			g.AddEdge(node, moduleExitNode)
		}
	}

	g.AddNode(moduleCallNode)
	g.AddNode(moduleExitNode)
	g.AddEdge(moduleCallNode, moduleExitNode)
	if parentCall != nil {
		g.AddEdge(parentCall, moduleCallNode)
	}
	if parentExit != nil {
		g.AddEdge(moduleExitNode, parentExit)
	}

	for _, childModule := range module.Children {
		if err := buildModuleNodes(g, childModule, moduleCallNode, moduleExitNode); err != nil {
			return err
		}
	}
	return nil
}

func buildEdges(g *graph) error {
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
				if addr.Mode == ManagedMode {
					if _, exists := g.managedResources[addr.Type]; !exists {
						continue
					}
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
				return fmt.Errorf("dependency node %s not found for node %s",
					ref.Addr.Key(), node.ID())
			}
			g.AddEdge(depNode, node)
		}
	}

	return nil
}

func (g *graph) String() string {
	var sb strings.Builder
	sb.WriteString("digraph G {\n")
	for _, node := range g.nodes {
		for dep := range g.Dependents(node) {
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
