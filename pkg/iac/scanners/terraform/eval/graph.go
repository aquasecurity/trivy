package eval

import (
	"errors"
	"fmt"
	"iter"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

type graph struct {
	nodes           map[string]Node
	dependentNodes  map[string]set.Set[string]
	dependencyNodes map[string]set.Set[string]

	managedResources set.Set[string]
}

func NewGraph() *graph {
	return &graph{
		nodes:            make(map[string]Node),
		dependentNodes:   make(map[string]set.Set[string]),
		dependencyNodes:  make(map[string]set.Set[string]),
		managedResources: set.New[string](),
	}
}

func (g *graph) Build(rootModule *ModuleConfig) error {
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
	g.dependencyNodes[id] = set.New[string]()
	g.dependentNodes[id] = set.New[string]()
}

func (n *graph) dependents(node Node) iter.Seq[string] {
	return n.dependentNodes[node.ID()].Iter()
}

func (n *graph) dependencies(node Node) iter.Seq[string] {
	return n.dependencyNodes[node.ID()].Iter()
}

func (g *graph) addEdge(dependency, dependent Node) {
	g.addDependent(dependency, dependent)
	g.addDependency(dependent, dependency)
}

func (n *graph) addDependent(src, target Node) {
	if n.dependentNodes[src.ID()] == nil {
		n.dependentNodes[src.ID()] = set.New[string]()
	}
	n.dependentNodes[src.ID()].Append(target.ID())
}

func (n *graph) addDependency(src, target Node) {
	if n.dependencyNodes[src.ID()] == nil {
		n.dependencyNodes[src.ID()] = set.New[string]()
	}
	n.dependencyNodes[src.ID()].Append(target.ID())
}

func (g *graph) TopoSort() ([]Node, error) {
	inDegree := make(map[string]int)
	for id := range g.nodes {
		inDegree[id] = 0
	}

	for _, n := range g.nodes {
		for dep := range g.dependents(n) {
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
		for dep := range g.dependents(n) {
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

func (g *graph) buildRealNodes(module *ModuleConfig) error {
	moduleAddr := module.AbsAddr()
	for _, block := range module.Blocks {
		switch blockType := block.underlying.Type; blockType {
		case "locals":
			for _, attr := range block.attrs {
				nodeId := moduleAddr.BlockAddr(LocalAddr{Name: attr.name})
				g.addNode(&NodeLocal{
					BaseNode:            newBaseNode(nodeId, moduleAddr),
					AttributeReferencer: &AttributeReferencer{Attr: attr},
					Name:                attr.name,
				})
			}
		case "output":
			name := block.underlying.Labels[0]
			nodeId := moduleAddr.BlockAddr(OutputAddr{Name: name})
			g.addNode(&NodeOutput{
				BaseNode:            newBaseNode(nodeId, moduleAddr),
				AttributeReferencer: &AttributeReferencer{Attr: block.attrs["value"]},
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
		Block:    module.Block,
		Name:     module.Name,
		Call:     module.ModuleCalls[module.Name],
	}
	moduleExitNode := &NodeModuleExit{
		BaseNode: newBaseNode(moduleAddr, moduleAddr.Parent()),
	}

	for _, node := range g.nodes {
		if node.Module().Equal(moduleAddr) {
			g.addEdge(moduleCallNode, node)
			g.addEdge(node, moduleExitNode)
		}
	}

	g.addNode(moduleCallNode)
	g.addNode(moduleExitNode)
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
				log.Debug("dependency node not found for node",
					log.String("node", ref.Addr.Key()), log.String("dependency", node.ID()))
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
