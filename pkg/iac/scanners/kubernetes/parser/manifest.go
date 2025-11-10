package parser

import (
	"fmt"

	"github.com/samber/lo"
	"gopkg.in/yaml.v3"

	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type Manifest struct {
	FilePath string
	Content  *ManifestNode
}

func NewManifest(path string, root *ManifestNode) (*Manifest, error) {
	if root.Type != TagMap {
		return &Manifest{FilePath: path}, nil
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
		FilePath: path,
		Content:  root,
	}, nil
}

func (m *Manifest) ToRego() any {
	if m.Content == nil {
		return nil
	}
	return m.Content.ToRego()
}

func ManifestFromJSON(path string, data []byte) (*Manifest, error) {
	var root = &ManifestNode{}
	if err := xjson.Unmarshal(data, root); err != nil {
		return nil, fmt.Errorf("unmarshal json: %w", err)
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
