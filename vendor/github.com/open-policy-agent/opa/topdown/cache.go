// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/util"
)

type virtualCache struct {
	stack []*virtualCacheElem
}

type virtualCacheElem struct {
	value    *ast.Term
	children *util.HashMap
}

func newVirtualCache() *virtualCache {
	cache := &virtualCache{}
	cache.Push()
	return cache
}

func (c *virtualCache) Push() {
	c.stack = append(c.stack, newVirtualCacheElem())
}

func (c *virtualCache) Pop() {
	c.stack = c.stack[:len(c.stack)-1]
}

func (c *virtualCache) Get(ref ast.Ref) *ast.Term {
	node := c.stack[len(c.stack)-1]
	for i := 0; i < len(ref); i++ {
		x, ok := node.children.Get(ref[i])
		if !ok {
			return nil
		}
		node = x.(*virtualCacheElem)
	}
	return node.value
}

func (c *virtualCache) Put(ref ast.Ref, value *ast.Term) {
	node := c.stack[len(c.stack)-1]
	for i := 0; i < len(ref); i++ {
		x, ok := node.children.Get(ref[i])
		if ok {
			node = x.(*virtualCacheElem)
		} else {
			next := newVirtualCacheElem()
			node.children.Put(ref[i], next)
			node = next
		}
	}
	node.value = value
}

func newVirtualCacheElem() *virtualCacheElem {
	return &virtualCacheElem{children: newVirtualCacheHashMap()}
}

func newVirtualCacheHashMap() *util.HashMap {
	return util.NewHashMap(func(a, b util.T) bool {
		return a.(*ast.Term).Equal(b.(*ast.Term))
	}, func(x util.T) int {
		return x.(*ast.Term).Hash()
	})
}

// baseCache implements a trie structure to cache base documents read out of
// storage. Values inserted into the cache may contain other values that were
// previously inserted. In this case, the previous values are erased from the
// structure.
type baseCache struct {
	root *baseCacheElem
}

func newBaseCache() *baseCache {
	return &baseCache{
		root: newBaseCacheElem(),
	}
}

func (c *baseCache) Get(ref ast.Ref) ast.Value {
	node := c.root
	for i := 0; i < len(ref); i++ {
		node = node.children[ref[i].Value]
		if node == nil {
			return nil
		} else if node.value != nil {
			result, err := node.value.Find(ref[i+1:])
			if err != nil {
				return nil
			}
			return result
		}
	}
	return nil
}

func (c *baseCache) Put(ref ast.Ref, value ast.Value) {
	node := c.root
	for i := 0; i < len(ref); i++ {
		if child, ok := node.children[ref[i].Value]; ok {
			node = child
		} else {
			child := newBaseCacheElem()
			node.children[ref[i].Value] = child
			node = child
		}
	}
	node.set(value)
}

type baseCacheElem struct {
	value    ast.Value
	children map[ast.Value]*baseCacheElem
}

func newBaseCacheElem() *baseCacheElem {
	return &baseCacheElem{
		children: map[ast.Value]*baseCacheElem{},
	}
}

func (e *baseCacheElem) set(value ast.Value) {
	e.value = value
	e.children = map[ast.Value]*baseCacheElem{}
}

type refStack struct {
	sl []refStackElem
}

type refStackElem struct {
	refs []ast.Ref
}

func newRefStack() *refStack {
	return &refStack{}
}

func (s *refStack) Push(refs []ast.Ref) {
	s.sl = append(s.sl, refStackElem{refs: refs})
}

func (s *refStack) Pop() {
	s.sl = s.sl[:len(s.sl)-1]
}

func (s *refStack) Prefixed(ref ast.Ref) bool {
	if s != nil {
		for i := len(s.sl) - 1; i >= 0; i-- {
			for j := range s.sl[i].refs {
				if ref.HasPrefix(s.sl[i].refs[j]) {
					return true
				}
			}
		}
	}
	return false
}

type comprehensionCache struct {
	stack []map[*ast.Term]*comprehensionCacheElem
}

type comprehensionCacheElem struct {
	value    *ast.Term
	children *util.HashMap
}

func newComprehensionCache() *comprehensionCache {
	cache := &comprehensionCache{}
	cache.Push()
	return cache
}

func (c *comprehensionCache) Push() {
	c.stack = append(c.stack, map[*ast.Term]*comprehensionCacheElem{})
}

func (c *comprehensionCache) Pop() {
	c.stack = c.stack[:len(c.stack)-1]
}

func (c *comprehensionCache) Elem(t *ast.Term) (*comprehensionCacheElem, bool) {
	elem, ok := c.stack[len(c.stack)-1][t]
	return elem, ok
}

func (c *comprehensionCache) Set(t *ast.Term, elem *comprehensionCacheElem) {
	c.stack[len(c.stack)-1][t] = elem
}

func newComprehensionCacheElem() *comprehensionCacheElem {
	return &comprehensionCacheElem{children: newComprehensionCacheHashMap()}
}

func (c *comprehensionCacheElem) Get(key []*ast.Term) *ast.Term {
	node := c
	for i := 0; i < len(key); i++ {
		x, ok := node.children.Get(key[i])
		if !ok {
			return nil
		}
		node = x.(*comprehensionCacheElem)
	}
	return node.value
}

func (c *comprehensionCacheElem) Put(key []*ast.Term, value *ast.Term) {
	node := c
	for i := 0; i < len(key); i++ {
		x, ok := node.children.Get(key[i])
		if ok {
			node = x.(*comprehensionCacheElem)
		} else {
			next := newComprehensionCacheElem()
			node.children.Put(key[i], next)
			node = next
		}
	}
	node.value = value
}

func newComprehensionCacheHashMap() *util.HashMap {
	return util.NewHashMap(func(a, b util.T) bool {
		return a.(*ast.Term).Equal(b.(*ast.Term))
	}, func(x util.T) int {
		return x.(*ast.Term).Hash()
	})
}

type functionMocksStack struct {
	stack []*functionMocksElem
}

type functionMocksElem []frame

type frame map[string]*ast.Term

func newFunctionMocksStack() *functionMocksStack {
	stack := &functionMocksStack{}
	stack.Push()
	return stack
}

func newFunctionMocksElem() *functionMocksElem {
	return &functionMocksElem{}
}

func (s *functionMocksStack) Push() {
	s.stack = append(s.stack, newFunctionMocksElem())
}

func (s *functionMocksStack) Pop() {
	s.stack = s.stack[:len(s.stack)-1]
}

func (s *functionMocksStack) PopPairs() {
	current := s.stack[len(s.stack)-1]
	*current = (*current)[:len(*current)-1]
}

func (s *functionMocksStack) PutPairs(mocks [][2]*ast.Term) {
	el := frame{}
	for i := range mocks {
		el[mocks[i][0].Value.String()] = mocks[i][1]
	}
	s.Put(el)
}

func (s *functionMocksStack) Put(el frame) {
	current := s.stack[len(s.stack)-1]
	*current = append(*current, el)
}

func (s *functionMocksStack) Get(f ast.Ref) (*ast.Term, bool) {
	current := *s.stack[len(s.stack)-1]
	for i := len(current) - 1; i >= 0; i-- {
		if r, ok := current[i][f.String()]; ok {
			return r, true
		}
	}
	return nil, false
}
