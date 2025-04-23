package parser

import (
	"fmt"
	"io/fs"
	"path"
	"time"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/ast"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func TransformASTToCF(fsys fs.FS, filePath string, root *ast.Node) (*FileContext, error) {
	fctx := &FileContext{
		filepath:   filePath,
		Parameters: make(map[string]*Parameter),
		Resources:  make(map[string]*Resource),
		Mappings:   make(map[string]any),
		Conditions: make(map[string]Property),
	}

	transformer := &ASTToCFTransformer{
		fsys:     fsys,
		filePath: filePath,
		fctx:     fctx,
	}

	if err := transformer.processNode(root); err != nil {
		return nil, err
	}

	return fctx, nil
}

type ASTToCFTransformer struct {
	fsys     fs.FS
	filePath string
	fctx     *FileContext
}

func (t *ASTToCFTransformer) processNode(n *ast.Node) error {
	children, err := getNodeMap(n, "root")
	if err != nil {
		return err
	}

	for key, child := range children {
		var err error
		switch key {
		case "Parameters":
			err = t.handleParameters(child)
		case "Resources":
			err = t.handleResources(child)
		case "Mappings":
			err = t.processMappings(child)
		case "Conditions":
			err = t.handleConditions(child)
		}
		if err != nil {
			return fmt.Errorf("failed to process %q: %w", key, err)
		}
	}

	return nil
}

func (t *ASTToCFTransformer) handleParameters(node *ast.Node) error {
	return t.handleSection(node, "parameters", func(children map[string]*ast.Node) error {
		for name, paramNode := range children {
			param := &Parameter{}
			if err := t.processParameter(paramNode, param); err != nil {
				return fmt.Errorf("process parameter %q: %w", name, err)
			}
			t.fctx.Parameters[name] = param
		}
		return nil
	})
}

func (t *ASTToCFTransformer) handleResources(node *ast.Node) error {
	return t.handleSection(node, "resources", func(children map[string]*ast.Node) error {
		for name, resNode := range children {
			startLine := resNode.StartLine
			if isYAML(t.filePath) {
				startLine--
			}
			resource := &Resource{
				ctx: t.fctx,
				id:  name,
				rng: iacTypes.NewRange(t.filePath, startLine, resNode.EndLine, "", t.fsys),
			}
			if err := t.processResource(resNode, resource); err != nil {
				return fmt.Errorf("process resource %q: %w", name, err)
			}
			t.fctx.Resources[name] = resource
		}
		return nil
	})
}

func (t *ASTToCFTransformer) handleConditions(node *ast.Node) error {
	conditionsRange := iacTypes.NewRange(t.filePath, node.StartLine, node.EndLine, "", t.fsys)
	return t.handleSection(node, "conditions", func(children map[string]*ast.Node) error {
		for name, condNode := range children {
			prop := Property{
				ctx:         t.fctx,
				name:        name,
				rng:         conditionsRange.SubRange(condNode.StartLine, condNode.EndLine),
				parentRange: conditionsRange,
			}
			if err := t.processProperty(condNode, &prop); err != nil {
				return fmt.Errorf("process condition %q: %w", name, err)
			}
			t.fctx.Conditions[name] = prop
		}
		return nil
	})
}

func (t *ASTToCFTransformer) processParameter(n *ast.Node, param *Parameter) error {
	if n.Value == nil {
		return nil
	}

	children, ok := n.Value.(map[string]*ast.Node)
	if !ok {
		return fmt.Errorf("expected parameter to be a map, got %T", n.Value)
	}

	if typNode, ok := children["Type"]; ok && typNode.Value != nil {
		str, ok := typNode.Value.(string)
		if !ok {
			return fmt.Errorf("parameter Type must be string, got %T", typNode.Value)
		}
		param.Typ = str
	}

	if defaultNode, ok := children["Default"]; ok && defaultNode.Value != nil {
		param.Default = defaultNode.Value
	}

	return nil
}

func (t *ASTToCFTransformer) processResource(n *ast.Node, resource *Resource) error {
	if n.Value == nil {
		return nil
	}

	children, ok := n.Value.(map[string]*ast.Node)
	if !ok {
		return fmt.Errorf("resource node: expected map[string]*ast.Node, got %T", n.Value)
	}

	if typNode, ok := children["Type"]; ok && typNode.Value != nil {
		str, ok := typNode.Value.(string)
		if !ok {
			return fmt.Errorf("resource Type must be string, got %T", typNode.Value)
		}
		resource.typ = str
	}

	resource.properties = make(map[string]*Property)
	props, exists := children["Properties"]
	if !exists {
		return nil
	}
	propNodes, ok := props.Value.(map[string]*ast.Node)
	if !ok {
		return nil
	}
	for key, child := range propNodes {
		property := &Property{
			ctx:         t.fctx,
			name:        key,
			rng:         resource.rng.SubRange(child.StartLine, child.EndLine),
			parentRange: resource.rng,
			logicalId:   resource.id,
		}
		if err := t.processProperty(child, property); err != nil {
			return err
		}
		resource.properties[key] = property
	}
	return nil
}

func (t *ASTToCFTransformer) processMappings(n *ast.Node) error {
	if n.Value == nil {
		return nil
	}

	children, ok := n.Value.(map[string]*ast.Node)
	if !ok {
		return fmt.Errorf("expected mappings to be a map, got %T", n.Value)
	}
	for key, child := range children {
		t.fctx.Mappings[key] = mappingToValue(child.Value)
	}

	return nil
}

func (t *ASTToCFTransformer) processProperty(n *ast.Node, property *Property) error {
	if n == nil || n.Value == nil {
		return nil
	}

	switch n.Kind {
	case ast.MappingNode:
		return t.processMappingNode(n, property)
	case ast.SequenceNode:
		return t.processSequenceNode(n, property)
	case ast.StringNode, ast.IntNode, ast.FloatNode, ast.BoolNode:
		property.Type = typeFromASTKind(n.Kind)
		property.Value = n.Value
	case ast.BinaryNode:
		property.Type = cftypes.String
		if v, ok := n.Value.([]byte); ok {
			property.Value = string(v)
		}
	case ast.TimestampNode:
		property.Type = cftypes.String
		if v, ok := n.Value.(time.Time); ok {
			property.Value = v.String()
		}
	case ast.NullNode:
		property.Type = cftypes.Unknown
		property.Value = nil
	default:
		return fmt.Errorf("unsupported node kind %s", n.Kind)
	}
	return nil
}

func (t *ASTToCFTransformer) processMappingNode(n *ast.Node, property *Property) error {
	children, ok := n.Value.(map[string]*ast.Node)
	if !ok {
		return fmt.Errorf("expected map for MappingNode, got %T", n.Value)
	}

	m := make(map[string]*Property)
	for key, child := range children {
		childProp := &Property{
			name:        key,
			ctx:         property.ctx,
			rng:         property.rng.SubRange(child.StartLine, child.EndLine),
			parentRange: property.rng,
		}

		if !isFunctionNode(child) {
			childProp.logicalId = property.logicalId
		}

		if err := t.processProperty(child, childProp); err != nil {
			return err
		}
		m[key] = childProp
	}

	property.Type = cftypes.Map
	property.Value = m
	return nil
}

func (t *ASTToCFTransformer) processSequenceNode(n *ast.Node, property *Property) error {
	items, ok := n.Value.([]*ast.Node)
	if !ok {
		return fmt.Errorf("expected slice for SequenceNode, got %T", n.Value)
	}

	var list []*Property
	for _, item := range items {
		elemProp := &Property{
			ctx:         property.ctx,
			rng:         property.rng.SubRange(item.StartLine, item.EndLine),
			parentRange: property.rng,
		}

		if err := t.processProperty(item, elemProp); err != nil {
			return err
		}
		list = append(list, elemProp)
	}

	property.Type = cftypes.List
	property.Value = list
	return nil
}

func (t *ASTToCFTransformer) handleSection(node *ast.Node, sectionName string, handler func(map[string]*ast.Node) error) error {
	children, err := getNodeMap(node, sectionName)
	if err != nil {
		return err
	}
	return handler(children)
}

func getNodeMap(node *ast.Node, section string) (map[string]*ast.Node, error) {
	if node == nil || node.Value == nil {
		return nil, nil
	}
	children, ok := node.Value.(map[string]*ast.Node)
	if !ok {
		return nil, fmt.Errorf("%s node: expected map[string]*ast.Node, got %T", section, node.Value)
	}
	return children, nil
}

func mappingToValue(v any) any {
	switch vv := v.(type) {
	case map[string]*ast.Node:
		return lo.MapValues(vv, func(n *ast.Node, _ string) any {
			return mappingToValue(n)
		})
	case []*ast.Node:
		return lo.Map(vv, func(n *ast.Node, _ int) any {
			return mappingToValue(n)
		})
	case *ast.Node:
		return mappingToValue(vv.Value)
	default:
		return v
	}
}

func typeFromASTKind(kind ast.NodeKind) cftypes.CfType {
	switch kind {
	case ast.StringNode:
		return cftypes.String
	case ast.IntNode:
		return cftypes.Int
	case ast.FloatNode:
		return cftypes.Float64
	case ast.BoolNode:
		return cftypes.Bool
	default:
		return cftypes.Unknown
	}
}

func isYAML(filePath string) bool {
	return path.Ext(filePath) == ".yml" || path.Ext(filePath) == ".yaml"
}

func isFunctionNode(n *ast.Node) bool {
	mapNode, ok := n.Value.(map[string]*ast.Node)
	if !ok {
		return false
	}
	return lo.SomeBy(lo.Keys(mapNode), IsIntrinsic)
}
