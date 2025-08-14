package inventory_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/inventory"
)

func makeSampleMap() *inventory.OrderedMap[string, int] {
	return inventory.NewOrderedMap(
		[]string{"a", "b", "c"},
		map[string]int{"a": 1, "b": 2, "c": 3},
	)
}

func TestOrderedMap_UnmarshalYAML(t *testing.T) {
	yamlData := `
a: 1
b: 2
c: 3
`
	var om inventory.OrderedMap[string, int]
	err := yaml.Unmarshal([]byte(yamlData), &om)
	require.NoError(t, err)

	m := make(map[string]int)
	var keys []string
	for k, v := range om.Iter() {
		m[k] = v
		keys = append(keys, k)
	}

	expectedMap := map[string]int{"a": 1, "b": 2, "c": 3}
	assert.Equal(t, expectedMap, m)

	expectedKeys := []string{"a", "b", "c"}
	assert.Equal(t, expectedKeys, keys)
}

func TestOrderedMap_Iter(t *testing.T) {
	m := makeSampleMap()

	collected := make(map[string]int)
	var order []string
	for k, v := range m.Iter() {
		collected[k] = v
		order = append(order, k)
	}

	assert.Equal(t, map[string]int{"a": 1, "b": 2, "c": 3}, collected)
	assert.Equal(t, []string{"a", "b", "c"}, order)
}
