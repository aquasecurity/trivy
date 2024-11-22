package terraform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zclconf/go-cty/cty"
)

type moduleBlock struct {
	name       string
	countIndex int
	index      cty.Value
	parent     *moduleBlock
}

func module(name string) *moduleBlock {
	return &moduleBlock{
		name: name,
	}
}

func (m *moduleBlock) withCountIndex(index int64) *moduleBlock {
	m.index = cty.NumberIntVal(index)
	return m
}

func (m *moduleBlock) withForEachIndex(index string) *moduleBlock {
	m.index = cty.StringVal(index)
	return m
}

func (m *moduleBlock) withParent(parent *moduleBlock) *moduleBlock {
	m.parent = parent
	return m
}

func (m *moduleBlock) build(t *testing.T) *Block {
	var parent *Block
	var parentName string
	if m.parent != nil {
		parentName = m.parent.name
		parent = m.parent.build(t)
	}
	ref, err := newReference([]string{"module", m.name}, parentName)
	assert.NoError(t, err)
	if m.index != cty.NilVal {
		ref.SetKey(m.index)
	}
	return &Block{
		reference:   *ref,
		moduleBlock: parent,
	}
}

func Test_ModuleName(t *testing.T) {
	testCases := map[string]struct {
		module             *moduleBlock
		expectedFullName   string
		expectedModuleName string
	}{
		"Simple module": {
			module:             module("my_module"),
			expectedFullName:   "module.my_module",
			expectedModuleName: "my_module",
		},
		"Nested modules": {
			module: module("grandchild").
				withParent(module("child").
					withParent(module("parent"))),
			expectedFullName:   "module.parent.module.child.module.grandchild",
			expectedModuleName: "parent.child.grandchild",
		},
		"Module with count index": {
			module:             module("my_module").withCountIndex(0),
			expectedFullName:   "module.my_module[0]",
			expectedModuleName: "my_module",
		},
		"Module with for_each index": {
			module:             module("my_module").withForEachIndex("instance"),
			expectedFullName:   "module.my_module[\"instance\"]",
			expectedModuleName: "my_module",
		},
		"Complex nesting with indices 1": {
			module: module("grandchild").withForEachIndex("index").
				withParent(module("child").withCountIndex(1).
					withParent(module("parent"))),
			expectedFullName:   "module.parent.module.child[1].module.grandchild[\"index\"]",
			expectedModuleName: "parent.child.grandchild",
		},
		"Complex nesting with indices 2": {
			module: module("grandchild").withForEachIndex("index_grandchild").
				withParent(module("child").withCountIndex(1).
					withParent(module("parent").withForEachIndex("index_parent"))),
			expectedFullName:   "module.parent[\"index_parent\"].module.child[1].module.grandchild[\"index_grandchild\"]",
			expectedModuleName: "parent.child.grandchild",
		},
		"Module name containing 'module' in its name": {
			module:             module("module_test"),
			expectedFullName:   "module.module_test",
			expectedModuleName: "module_test",
		},
		"Module with 'module' in the middle of the name": {
			module: module("grandchild_module").
				withParent(module("child_module").
					withParent(module("parent_module"))),
			expectedFullName:   "module.parent_module.module.child_module.module.grandchild_module",
			expectedModuleName: "parent_module.child_module.grandchild_module",
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			m := test.module.build(t)
			assert.Equal(t, test.expectedFullName, m.FullName())
			assert.Equal(t, test.expectedModuleName, m.ModuleName())
		})
	}
}
