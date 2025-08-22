package inventory

import (
	"iter"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	"github.com/aquasecurity/trivy/pkg/set"
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
	if n.Kind != yaml.MappingNode {
		return xerrors.Errorf("expected map node, got %s", n.Tag)
	}

	if len(n.Content)%2 != 0 {
		return xerrors.New("invalid map node content length")
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

	inv := newInventory()

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
	// Add group
	newGroup := newGroup(rg.Vars, set.New(parents...))
	inv.addGroup(name, newGroup)

	// Add hosts
	// A host can be in multiple groups, but Ansible processes only one instance of the host at runtime.
	// Ansible merges the data from multiple groups.
	for hostName, hostVars := range rg.Hosts {
		groups := set.New(append(parents, name)...)
		// TODO: support for host ranges, e.g. www[01:50:2].example.com
		// https://docs.ansible.com/ansible/latest/inventory_guide/intro_inventory.html#adding-ranges-of-hosts
		inv.addHost(hostName, newHost(hostVars, groups))
	}

	// Recursively parse children groups
	for childName, childRg := range rg.Children.Iter() {
		parseGroup(childName, childRg, inv, append(parents, name))
	}
	return nil
}
