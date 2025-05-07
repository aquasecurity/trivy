package parser

import (
	"fmt"

	"github.com/samber/lo"
	"gopkg.in/yaml.v3"

	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type Manifest struct {
	Path    string
	Content *ManifestNode
}

func NewManifest(path string, root *ManifestNode) *Manifest {
	root.Walk(func(n *ManifestNode) {
		n.Path = path
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
	}
}

func (m *Manifest) UnmarshalYAML(value *yaml.Node) error {
	switch value.Tag {
	case string(TagMap):
		node := new(ManifestNode)
		node.Path = m.Path
		if err := value.Decode(node); err != nil {
			return err
		}
		m.Content = node
	default:
		return fmt.Errorf("failed to handle tag: %s", value.Tag)
	}

	return nil
}

func (m *Manifest) ToRego() any {
	return m.Content.ToRego()
}

func ManifestFromJSON(path string, data []byte) (*Manifest, error) {
	root := &ManifestNode{}

	if err := xjson.Unmarshal(data, root); err != nil {
		return nil, err
	}

	return NewManifest(path, root), nil
}
