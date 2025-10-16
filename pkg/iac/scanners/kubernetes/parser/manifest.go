package parser

import (
	"fmt"
	"strings"

	"github.com/samber/lo"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/generic"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type Manifest struct {
	Path    string
	Content *ManifestNode
}

func NewManifest(path string, root *ManifestNode) (*Manifest, error) {
	if root.Type != TagMap {
		return nil, fmt.Errorf("root node must be a map, but got: %s", root.Type)
	}

	root.Walk(func(n *ManifestNode) {
		n.FilePath = path
		switch v := n.Value.(type) {
		case []*ManifestNode:
			n.Value = lo.Filter(v, func(vv *ManifestNode, _ int) bool {
				return vv != nil
			})
		case map[string]*ManifestNode:
			n.Value = lo.OmitBy(v, func(_ string, vv *ManifestNode) bool {
				return vv == nil
			})
		}
	})
	return &Manifest{
		Path:    path,
		Content: root,
	}, nil
}

var (
	_ generic.RegoMarshaler     = (*Manifest)(nil)
	_ generic.LogicalPathFinder = (*Manifest)(nil)
)

func (m *Manifest) ToRego() any {
	return m.Content.ToRego()
}

func (m *Manifest) ResolveLogicalPath(filename string, startLine, endLine int) generic.LogicalPath {
	if m == nil || m.Content == nil {
		return generic.LogicalPath{}
	}

	if m.Path != filename {
		return generic.LogicalPath{}
	}

	var parts []string

	var walk func(name string, n *ManifestNode) bool
	walk = func(name string, n *ManifestNode) bool {

		// match
		if n.Type.Primitive() && n.StartLine == startLine && n.EndLine == endLine {
			parts = append(parts, name)
			return true
		}

		// includes
		if n.StartLine <= startLine && n.EndLine >= endLine {
			switch v := n.Value.(type) {
			case []*ManifestNode:
				for i, child := range v {
					childName := fmt.Sprintf("%s[%d/%d]", name, i, len(v)-1)
					if walk(childName, child) {
						return true
					}
				}
			case map[string]*ManifestNode:
				parts = append(parts, name)
				for childName, child := range v {
					if walk(childName, child) {
						return true
					}
				}
			}
			return true
		}
		return false
	}

	// The root node is always a map.
	if root, ok := m.Content.Value.(map[string]*ManifestNode); ok {
		for k, child := range root {
			if walk(k, child) {
				break
			}
		}
	}

	return generic.LogicalPath{
		Val: strings.Join(parts, "."),
	}
}

func ManifestFromJSON(path string, data []byte) (*Manifest, error) {
	var root = &ManifestNode{}

	if err := xjson.Unmarshal(data, root); err != nil {
		return nil, err
	}

	return NewManifest(path, root)
}

func ManifestFromYAML(path string, data []byte) (*Manifest, error) {
	var root = &ManifestNode{}
	if err := yaml.Unmarshal(data, root); err != nil {
		return nil, fmt.Errorf("unmarshal yaml: %w", err)
	}

	return NewManifest(path, root)
}
