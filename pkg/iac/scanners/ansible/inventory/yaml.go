package inventory

import (
	"iter"
	"maps"
	"slices"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

// OrderedMap is a map that preserves insertion order of keys.
type OrderedMap[K comparable, V any] struct {
	keys []K
	kv   map[K]V
}

func NewOrderedMap[K comparable, V any](keys []K, kv map[K]V) *OrderedMap[K, V] {
	return &OrderedMap[K, V]{keys: keys, kv: kv}
}

// Len returns the number of entires in the map
func (m *OrderedMap[K, V]) Len() int {
	return len(m.keys)
}

// Iter returns an iterator over the map
func (m *OrderedMap[K, V]) Iter() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for _, k := range m.keys {
			v := m.kv[k]
			if !yield(k, v) {
				return
			}
		}
	}
}

func (m *OrderedMap[K, V]) UnmarshalYAML(n *yaml.Node) error {
	if n.Tag != "!!map" {
		return xerrors.Errorf("expected map node, got %s", n.Tag)
	}

	if len(n.Content)%2 != 0 {
		return xerrors.Errorf("invalid map node content length")
	}

	size := len(n.Content) / 2
	m.keys = make([]K, 0, size)
	m.kv = make(map[K]V, size)

	for i := 0; i < len(n.Content); i += 2 {
		keyNode, valueNode := n.Content[i], n.Content[i+1]

		var key K
		if err := keyNode.Decode(&key); err != nil {
			return err
		}
		m.keys = append(m.keys, key)

		var value V
		if err := valueNode.Decode(&value); err != nil {
			return err
		}
		m.kv[key] = value
	}
	return nil
}

type rawGroup struct {
	Hosts    map[string]vars.Vars         `yaml:"hosts"`
	Children OrderedMap[string, rawGroup] `yaml:"children"`
	Vars     vars.Vars                    `yaml:"vars"`
}

func ParseYAML(data []byte) (*Inventory, error) {
	var raw OrderedMap[string, rawGroup]
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, xerrors.Errorf("unmarshal inventory yaml: %w", err)
	}

	inv := &Inventory{
		hosts:      make(map[string]*Host),
		groups:     make(map[string]*Group),
		hostGroups: make(map[string][]string),
	}

	for groupName, groupRaw := range raw.Iter() {
		if err := parseGroup(groupName, groupRaw, inv, nil); err != nil {
			return nil, err
		}
	}

	inv.initDefaultGroups()
	return inv, nil
}

// parseGroup recursively parses a rawGroup and adds it to Inventory
func parseGroup(name string, rg rawGroup, inv *Inventory, parents []string) error {
	group := &Group{
		Vars:     rg.Vars,
		Children: make([]string, 0, rg.Children.Len()),
		Parents:  slices.Clone(parents),
	}

	// Add hosts
	for hostName, hostVars := range rg.Hosts {

		if existingHost, exists := inv.hosts[hostName]; !exists {
			inv.hosts[hostName] = &Host{
				Vars: hostVars,
			}
		} else {
			maps.Copy(existingHost.Vars, hostVars)
		}

		inv.hostGroups[hostName] = append(inv.hostGroups[hostName], append(parents, name)...)
	}

	inv.groups[name] = group

	// Recursively add children
	for childName := range rg.Children.Iter() {
		childGroup, exists := inv.groups[childName]
		if !exists {
			childGroup = &Group{}
			inv.groups[childName] = childGroup
		}
		childGroup.Parents = append(childGroup.Parents, name)
		group.Children = append(group.Children, childName)
	}

	return nil
}
