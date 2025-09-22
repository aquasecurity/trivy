package parser

import (
	"cmp"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/fsutils"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/orderedmap"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

type NodeValue interface {
	MarshalYAML() (any, error)

	nodeValueMarker()
}

type Scalar struct {
	Val any
}

func (s *Scalar) MarshalYAML() (any, error) {
	if s.Val == nil {
		return nil, nil
	}
	return s.Val, nil
}

type Mapping struct {
	Fields *orderedmap.OrderedMap[string, *Node]
}

func (m *Mapping) MarshalYAML() (any, error) {
	node := &yaml.Node{
		Kind:    yaml.MappingNode,
		Tag:     "!!map",
		Content: nil,
	}
	for key, child := range m.Fields.Iter() {
		keyNode := &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: key,
		}
		valYAML, err := child.MarshalYAML()
		if err != nil {
			return nil, err
		}
		valNode := &yaml.Node{}
		if err := valNode.Encode(valYAML); err != nil {
			return nil, err
		}

		node.Content = append(node.Content, keyNode, valNode)
	}
	return node, nil
}

type Sequence struct {
	Items []*Node
}

func (s *Sequence) MarshalYAML() (any, error) {
	node := &yaml.Node{
		Kind:    yaml.SequenceNode,
		Tag:     "!!seq",
		Content: nil,
	}
	for _, item := range s.Items {
		itemYAML, err := item.MarshalYAML()
		if err != nil {
			return nil, err
		}
		itemNode := &yaml.Node{}
		if err := itemNode.Encode(itemYAML); err != nil {
			return nil, err
		}
		node.Content = append(node.Content, itemNode)
	}
	return node, nil
}

func (s *Scalar) nodeValueMarker()   {}
func (m *Mapping) nodeValueMarker()  {}
func (s *Sequence) nodeValueMarker() {}

type Node struct {
	rng      Range
	metadata iacTypes.Metadata
	val      NodeValue

	unknown bool
}

func (n *Node) Metadata() iacTypes.Metadata {
	return n.metadata
}

func (n *Node) IsKnown() bool {
	return !n.unknown
}

func (n *Node) UnmarshalYAML(node *yaml.Node) error {
	n.rng = rangeFromNode(node)

	switch node.Kind {
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!int":
			v, err := strconv.Atoi(node.Value)
			if err == nil {
				n.val = &Scalar{Val: v}
			}
		case "!!float":
			// TODO: handle float properly
		case "!!bool":
			v, err := strconv.ParseBool(node.Value)
			if err == nil {
				n.val = &Scalar{Val: v}
			}
		case StrTag, "!!string":
			n.val = &Scalar{Val: node.Value}
		}
		return nil
	case yaml.MappingNode:
		n.rng.Start--
		childData, err := decodeMapNode(node)
		if err != nil {
			return err
		}
		n.val = childData
		return nil
	case yaml.SequenceNode:
		n.rng.Start--
		childData, err := decodeSequenceNode(node)
		if err != nil {
			return err
		}
		n.val = childData
		return nil
	}
	return nil
}

func decodeMapNode(node *yaml.Node) (*Mapping, error) {
	childMap := orderedmap.New[string, *Node](len(node.Content) / 2)

	for i := 0; i < len(node.Content); i += 2 {
		keyNode, valueNode := node.Content[i], node.Content[i+1]

		childNode, err := decodeChildNode(valueNode)
		if err != nil {
			return nil, err
		}

		childMap.Set(keyNode.Value, &childNode)
	}

	return &Mapping{Fields: childMap}, nil
}

func decodeSequenceNode(node *yaml.Node) (*Sequence, error) {
	items := make([]*Node, 0, len(node.Content))

	for _, elemNode := range node.Content {
		childNode, err := decodeChildNode(elemNode)
		if err != nil {
			return nil, err
		}
		if elemNode.Kind == yaml.MappingNode {
			childNode.rng.Start++
		}
		items = append(items, &childNode)
	}

	return &Sequence{Items: items}, nil
}

func decodeChildNode(yNode *yaml.Node) (Node, error) {
	if yNode.Kind == yaml.ScalarNode && yNode.Tag == NullTag {
		return Node{
			rng: rangeFromNode(yNode),
			val: nil,
		}, nil
	}

	var n Node
	if err := yNode.Decode(&n); err != nil {
		return Node{}, err
	}
	return n, nil
}

func (n *Node) initMetadata(fileSrc fsutils.FileSource, parent *iacTypes.Metadata, nodePath []string) {
	fsys, relPath := fileSrc.FSAndRelPath()
	ref := cmp.Or(strings.Join(nodePath, "."), ".")
	rng := iacTypes.NewRange(relPath, n.rng.Start, n.rng.End, "", fsys)

	n.metadata = iacTypes.NewMetadata(rng, ref)
	n.metadata.SetParentPtr(parent)

	switch val := n.val.(type) {
	case *Mapping:
		for key, attr := range val.Fields.Iter() {
			if attr == nil {
				continue
			}
			childPath := append(nodePath, key)
			attr.initMetadata(fileSrc, parent, childPath)
		}
	case *Sequence:
		for idx, attr := range val.Items {
			if attr == nil {
				continue
			}
			childPath := append(nodePath, fmt.Sprintf("[%d]", idx))
			attr.initMetadata(fileSrc, parent, childPath)
		}
	}
}

func (n *Node) Render(variables vars.Vars) (*Node, error) {
	return n.render(variables, set.New[string]())
}

func (n *Node) render(variables vars.Vars, visited set.Set[string]) (*Node, error) {
	if n == nil {
		return nil, nil
	}

	switch v := n.val.(type) {
	case *Scalar:
		if s, ok := v.Val.(string); ok {
			if found := visited.Contains(s); found {
				return n, fmt.Errorf("cyclic reference detected: %q", s)
			}

			visited.Append(s)
			rendered, err := evaluateTemplate(s, variables)
			if err != nil {
				n.unknown = true
				return n, fmt.Errorf("node ref %q: %w", n.metadata.Reference(), err)
			}

			newNode := n.withValue(&Scalar{Val: rendered})
			if strings.Contains(rendered, "{{") {
				return newNode.render(variables, visited)
			}
			visited.Remove(s)

			return newNode, nil
		}
		return n, nil
	case *Mapping:
		var errs error
		fields := orderedmap.New[string, *Node](v.Fields.Len())
		for key, val := range v.Fields.Iter() {
			r, err := val.Render(variables)
			if err != nil {
				errs = multierror.Append(err)
			}
			fields.Set(key, r)
		}
		return n.withValue(&Mapping{Fields: fields}), errs
	case *Sequence:
		var errs error
		items := make([]*Node, 0, len(v.Items))
		for _, val := range v.Items {
			r, err := val.Render(variables)
			if err != nil {
				errs = multierror.Append(err)
			}
			items = append(items, r)
		}
		return n.withValue(&Sequence{Items: items}), errs
	default:
		return n, nil
	}
}

func (n *Node) withValue(val NodeValue) *Node {
	return &Node{val: val, rng: n.rng, metadata: n.metadata}
}

func (n *Node) MarshalYAML() (any, error) {
	if n.val == nil {
		return nil, nil
	}
	return n.val.MarshalYAML()
}

func (n *Node) IsNil() bool {
	return n == nil || n.val == nil
}

func (n *Node) IsMap() bool {
	return safeOp(n, func(nv NodeValue) bool {
		_, ok := nv.(*Mapping)
		return ok
	})
}

func (n *Node) IsList() bool {
	return safeOp(n, func(nv NodeValue) bool {
		_, ok := nv.(*Sequence)
		return ok
	})
}

func (n *Node) IsBool() bool {
	return checkScalarType[bool](n)
}

func (n *Node) IsString() bool {
	return checkScalarType[string](n)
}

func (n *Node) ToList() []*Node {
	return safeOp(n, func(nv NodeValue) []*Node {
		val, ok := nv.(*Sequence)
		if !ok || val == nil {
			return nil
		}

		return val.Items
	})
}

func (n *Node) ToMap() map[string]*Node {
	return safeOp(n, func(nv NodeValue) map[string]*Node {
		val, ok := nv.(*Mapping)
		if !ok || val == nil {
			return make(map[string]*Node)
		}

		return val.Fields.AsMap()
	})
}

func (n *Node) NodeAt(path string) *Node {
	if path == "" || !n.IsMap() {
		return nil
	}

	parts := strings.SplitN(path, ".", 2)

	attr, exists := n.ToMap()[parts[0]]
	if !exists {
		return nil
	}

	if len(parts) == 1 {
		return attr
	}

	return attr.NodeAt(parts[1])
}

func (n *Node) StringValue(path string) iacTypes.StringValue {
	def := iacTypes.StringDefault("", n.metadata)
	if n.IsNil() {
		return def
	}

	if n.unknown {
		return iacTypes.StringUnresolvable(n.metadata)
	}

	nested := n.NodeAt(path)
	val, ok := nested.AsString()
	if !ok {
		return iacTypes.StringUnresolvable(n.metadata)
	}
	return iacTypes.String(val, n.metadata)
}

func (n *Node) BoolValue(path string) iacTypes.BoolValue {
	def := iacTypes.BoolDefault(false, n.metadata)
	if n.IsNil() {
		return def
	}

	if n.unknown {
		return iacTypes.BoolUnresolvable(n.metadata)
	}

	nested := n.NodeAt(path)
	val, ok := nested.AsBool()
	if !ok {
		return iacTypes.BoolUnresolvable(n.metadata)
	}

	return iacTypes.Bool(val, iacTypes.Metadata{})
}

func (n *Node) AsBool() (bool, bool) {
	if n.IsNil() {
		return false, false
	}

	scalar, ok := n.val.(*Scalar)
	if !ok {
		return false, false
	}

	switch val := scalar.Val.(type) {
	case bool:
		return val, true
	case string:
		return parseAnsibleBool(val)
	case int:
		switch val {
		case 0:
			return false, true
		case 1:
			return true, true
		}
	}
	return false, false
}

// parseAnsibleBool implements Ansible's string→bool conversion.
func parseAnsibleBool(s string) (bool, bool) {
	normalized := strings.ToLower(strings.TrimSpace(s))

	switch normalized {
	case "1", "t", "true", "y", "yes", "on":
		return true, true
	case "0", "f", "false", "n", "no", "off":
		return false, true
	default:
		return false, false
	}
}

func (n *Node) AsString() (string, bool) {
	if !n.IsString() {
		return "", false
	}

	scalar, _ := n.val.(*Scalar)
	val, ok := scalar.Val.(string)
	return val, ok
}

func (n *Node) Value() any {
	return safeOp(n, func(nv NodeValue) any {
		scalar, ok := nv.(*Scalar)
		if ok {
			return scalar.Val
		}
		return nil
	})
}

func checkScalarType[T any](n *Node) bool {
	return safeOp(n, func(nv NodeValue) bool {
		scalar, ok := nv.(*Scalar)
		if !ok || scalar.Val == nil {
			return false
		}
		_, ok = scalar.Val.(T)
		return ok
	})
}

func safeOp[T any](n *Node, op func(NodeValue) T) T {
	var zero T
	if n.IsNil() || n.val == nil {
		return zero
	}
	return op(n.val)
}

func (n *Node) Subtree(r Range) *Node {
	sub, _ := n.subtree(r)
	return sub
}

func (n *Node) subtree(r Range) (*Node, bool) {
	if n == nil {
		return nil, false
	}

	if r.Covers(n.rng) {
		return n, false
	}

	switch val := n.val.(type) {
	case *Mapping:
		subFields := orderedmap.New[string, *Node](val.Fields.Len())
		for k, child := range val.Fields.Iter() {
			if child == nil {
				continue
			}
			sub, partial := child.subtree(r)
			if sub == nil {
				continue
			}

			if partial && r.Start > child.rng.Start {
				return sub, true
			}
			subFields.Set(k, sub)
		}
		if subFields.Len() > 0 {
			return n.withValue(&Mapping{Fields: subFields}), true
		}
		return nil, false
	case *Sequence:
		items := make([]*Node, 0, len(val.Items))
		for _, item := range val.Items {
			if item == nil {
				continue
			}
			sub, partial := item.subtree(r)
			if sub == nil {
				continue
			}
			if partial {
				// Return a new sequence containing only the partially matched element.
				return n.withValue(&Sequence{Items: []*Node{sub}}), true
			}

			items = append(items, sub)
		}
		if len(items) > 0 {
			return n.withValue(&Sequence{Items: items}), true
		}
		return nil, false
	default:
		if r.Overlaps(n.rng) {
			return n, false
		}
		return nil, false
	}
}
