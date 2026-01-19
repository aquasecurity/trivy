package orderedmap

import (
	"iter"
	"maps"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

// OrderedMap is a map that preserves insertion order of keys.
type OrderedMap[K comparable, V any] struct {
	keys []K
	data map[K]V
}

func New[K comparable, V any](capacity int) *OrderedMap[K, V] {
	return &OrderedMap[K, V]{
		keys: make([]K, 0, capacity),
		data: make(map[K]V, capacity),
	}
}

func NewWithData[K comparable, V any](keys []K, data map[K]V) *OrderedMap[K, V] {
	return &OrderedMap[K, V]{
		keys: keys,
		data: data,
	}
}

// Len returns the number of entires in the map
func (m *OrderedMap[K, V]) Len() int {
	return len(m.keys)
}

func (m *OrderedMap[K, V]) Get(key K) (V, bool) {
	val, ok := m.data[key]
	return val, ok
}

func (m *OrderedMap[K, V]) Set(key K, value V) {
	if _, exists := m.data[key]; !exists {
		m.keys = append(m.keys, key)
	}
	m.data[key] = value
}

// Iter returns an iterator over the map
func (m *OrderedMap[K, V]) Iter() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for _, k := range m.keys {
			v := m.data[k]
			if !yield(k, v) {
				return
			}
		}
	}
}

func (m *OrderedMap[K, V]) AsMap() map[K]V {
	return maps.Clone(m.data)
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
	m.data = make(map[K]V, size)

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
		m.data[key] = value
	}
	return nil
}
