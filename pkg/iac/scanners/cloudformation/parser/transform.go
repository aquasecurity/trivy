package parser

import (
	"fmt"
	"io/fs"
	"path"
	"time"

	"github.com/aquasecurity/trivy/pkg/iac/ast"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/samber/lo"
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
	if n.Kind != ast.MappingNode || n.Value == nil {
		return nil
	}

	children, ok := n.Value.(map[string]*ast.Node)
	if !ok {
		return fmt.Errorf("expected mapping node at root")
	}

	fileRange := iacTypes.NewRange(t.filePath, n.StartLine, n.EndLine, "", t.fsys)

	for key, child := range children {
		switch key {

		case "Parameters":
			if child.Value == nil {
				continue
			}
			paramNodes, ok := child.Value.(map[string]*ast.Node)
			if !ok {
				return fmt.Errorf("parameters node is not a map")
			}
			for name, paramNode := range paramNodes {
				param := &Parameter{}
				if err := t.processParameter(paramNode, param); err != nil {
					return fmt.Errorf("failed to process parameter %q: %w", name, err)
				}
				t.fctx.Parameters[name] = param
			}

		case "Resources":
			if child.Value == nil {
				continue
			}
			resourceNodes, ok := child.Value.(map[string]*ast.Node)
			if !ok {
				return fmt.Errorf("resources node is not a map")
			}
			for name, resNode := range resourceNodes {
				startLine := resNode.StartLine
				if isYAML(t.filePath) {
					startLine = startLine - 1
				}
				resource := &Resource{
					ctx: t.fctx,
					id:  name,
					rng: iacTypes.NewRange(t.filePath, startLine, resNode.EndLine, "", t.fsys),
				}
				if err := t.processResource(resNode, resource); err != nil {
					return fmt.Errorf("failed to process resource %q: %w", name, err)
				}
				t.fctx.Resources[name] = resource
			}

		case "Mappings":
			if err := t.processMappings(child); err != nil {
				return fmt.Errorf("failed to process Mappings: %w", err)
			}

		case "Conditions":
			if child.Value == nil {
				continue
			}
			conditionNodes, ok := child.Value.(map[string]*ast.Node)
			if !ok {
				return fmt.Errorf("conditions node is not a map")
			}

			for name, condNode := range conditionNodes {
				prop := Property{
					ctx:         t.fctx,
					name:        key,
					rng:         fileRange.SubRange(child.StartLine, child.EndLine),
					parentRange: fileRange,
				}
				if err := t.processProperty(condNode, &prop); err != nil {
					return fmt.Errorf("failed to process condition %q: %w", name, err)
				}
				t.fctx.Conditions[name] = prop
			}
		}
	}

	return nil
}

func (t *ASTToCFTransformer) processParameter(n *ast.Node, param *Parameter) error {
	if n.Value == nil {
		return nil
	}

	children, ok := n.Value.(map[string]*ast.Node)
	if !ok {
		return nil
	}

	if typNode, ok := children["Type"]; ok && typNode.Value != nil {
		param.Typ = typNode.Value.(string)
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
		return nil
	}

	if typNode, ok := children["Type"]; ok && typNode.Value != nil {
		resource.typ = typNode.Value.(string)
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
		return nil
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
		return fmt.Errorf("unsoppurted node %s", n.Kind)
	}

	return nil
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

func mappingToValue(v any) any {
	switch vv := v.(type) {
	case map[string]*ast.Node:
		return lo.MapValues(vv, func(v *ast.Node, _ string) any {
			return mappingToValue(v)
		})
	case []*ast.Node:
		return lo.Map(vv, func(n *ast.Node, _ int) any {
			return mappingToValue(v)
		})
	case *ast.Node:
		return mappingToValue(vv.Value)
	default:
		return v
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

	for key := range mapNode {
		return IsIntrinsic(key)
	}
	return false
}
