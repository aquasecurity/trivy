package parser

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type Manifest struct {
	Path    string
	Content *ManifestNode
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
