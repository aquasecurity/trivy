// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

import (
	"github.com/open-policy-agent/opa/types"
	"github.com/open-policy-agent/opa/util"
)

// TypeEnv contains type info for static analysis such as type checking.
type TypeEnv struct {
	tree       *typeTreeNode
	next       *TypeEnv
	newChecker func() *typeChecker
}

// newTypeEnv returns an empty TypeEnv. The constructor is not exported because
// type environments should only be created by the type checker.
func newTypeEnv(f func() *typeChecker) *TypeEnv {
	return &TypeEnv{
		tree:       newTypeTree(),
		newChecker: f,
	}
}

// Get returns the type of x.
func (env *TypeEnv) Get(x interface{}) types.Type {

	if term, ok := x.(*Term); ok {
		x = term.Value
	}

	switch x := x.(type) {

	// Scalars.
	case Null:
		return types.NewNull()
	case Boolean:
		return types.NewBoolean()
	case Number:
		return types.NewNumber()
	case String:
		return types.NewString()

	// Composites.
	case *Array:
		static := make([]types.Type, x.Len())
		for i := range static {
			tpe := env.Get(x.Elem(i).Value)
			static[i] = tpe
		}

		var dynamic types.Type
		if len(static) == 0 {
			dynamic = types.A
		}

		return types.NewArray(static, dynamic)

	case *object:
		static := []*types.StaticProperty{}
		var dynamic *types.DynamicProperty

		x.Foreach(func(k, v *Term) {
			if IsConstant(k.Value) {
				kjson, err := JSON(k.Value)
				if err == nil {
					tpe := env.Get(v)
					static = append(static, types.NewStaticProperty(kjson, tpe))
					return
				}
			}
			// Can't handle it as a static property, fallback to dynamic
			typeK := env.Get(k.Value)
			typeV := env.Get(v.Value)
			dynamic = types.NewDynamicProperty(typeK, typeV)
		})

		if len(static) == 0 && dynamic == nil {
			dynamic = types.NewDynamicProperty(types.A, types.A)
		}

		return types.NewObject(static, dynamic)

	case Set:
		var tpe types.Type
		x.Foreach(func(elem *Term) {
			other := env.Get(elem.Value)
			tpe = types.Or(tpe, other)
		})
		if tpe == nil {
			tpe = types.A
		}
		return types.NewSet(tpe)

	// Comprehensions.
	case *ArrayComprehension:
		cpy, errs := env.newChecker().CheckBody(env, x.Body)
		if len(errs) == 0 {
			return types.NewArray(nil, cpy.Get(x.Term))
		}
		return nil
	case *ObjectComprehension:
		cpy, errs := env.newChecker().CheckBody(env, x.Body)
		if len(errs) == 0 {
			return types.NewObject(nil, types.NewDynamicProperty(cpy.Get(x.Key), cpy.Get(x.Value)))
		}
		return nil
	case *SetComprehension:
		cpy, errs := env.newChecker().CheckBody(env, x.Body)
		if len(errs) == 0 {
			return types.NewSet(cpy.Get(x.Term))
		}
		return nil

	// Refs.
	case Ref:
		return env.getRef(x)

	// Vars.
	case Var:
		if node := env.tree.Child(x); node != nil {
			return node.Value()
		}
		if env.next != nil {
			return env.next.Get(x)
		}
		return nil

	// Calls.
	case Call:
		return nil

	default:
		panic("unreachable")
	}
}

func (env *TypeEnv) getRef(ref Ref) types.Type {

	node := env.tree.Child(ref[0].Value)
	if node == nil {
		return env.getRefFallback(ref)
	}

	return env.getRefRec(node, ref, ref[1:])
}

func (env *TypeEnv) getRefFallback(ref Ref) types.Type {

	if env.next != nil {
		return env.next.Get(ref)
	}

	if RootDocumentNames.Contains(ref[0]) {
		return types.A
	}

	return nil
}

func (env *TypeEnv) getRefRec(node *typeTreeNode, ref, tail Ref) types.Type {
	if len(tail) == 0 {
		return env.getRefRecExtent(node)
	}

	if node.Leaf() {
		return selectRef(node.Value(), tail)
	}

	if !IsConstant(tail[0].Value) {
		return selectRef(env.getRefRecExtent(node), tail)
	}

	child := node.Child(tail[0].Value)
	if child == nil {
		return env.getRefFallback(ref)
	}

	return env.getRefRec(child, ref, tail[1:])
}

func (env *TypeEnv) getRefRecExtent(node *typeTreeNode) types.Type {

	if node.Leaf() {
		return node.Value()
	}

	children := []*types.StaticProperty{}

	node.Children().Iter(func(k, v util.T) bool {
		key := k.(Value)
		child := v.(*typeTreeNode)

		tpe := env.getRefRecExtent(child)
		// TODO(tsandall): handle non-string keys?
		if s, ok := key.(String); ok {
			children = append(children, types.NewStaticProperty(string(s), tpe))
		}
		return false
	})

	// TODO(tsandall): for now, these objects can have any dynamic properties
	// because we don't have schema for base docs. Once schemas are supported
	// we can improve this.
	return types.NewObject(children, types.NewDynamicProperty(types.S, types.A))
}

func (env *TypeEnv) wrap() *TypeEnv {
	cpy := *env
	cpy.next = env
	cpy.tree = newTypeTree()
	return &cpy
}

// typeTreeNode is used to store type information in a tree.
type typeTreeNode struct {
	key      Value
	value    types.Type
	children *util.HashMap
}

func newTypeTree() *typeTreeNode {
	return &typeTreeNode{
		key:      nil,
		value:    nil,
		children: util.NewHashMap(valueEq, valueHash),
	}
}

func (n *typeTreeNode) Child(key Value) *typeTreeNode {
	value, ok := n.children.Get(key)
	if !ok {
		return nil
	}
	return value.(*typeTreeNode)
}

func (n *typeTreeNode) Children() *util.HashMap {
	return n.children
}

func (n *typeTreeNode) Get(path Ref) types.Type {
	curr := n
	for _, term := range path {
		child, ok := curr.children.Get(term.Value)
		if !ok {
			return nil
		}
		curr = child.(*typeTreeNode)
	}
	return curr.Value()
}

func (n *typeTreeNode) Leaf() bool {
	return n.value != nil
}

func (n *typeTreeNode) PutOne(key Value, tpe types.Type) {
	c, ok := n.children.Get(key)

	var child *typeTreeNode
	if !ok {
		child = newTypeTree()
		child.key = key
		n.children.Put(key, child)
	} else {
		child = c.(*typeTreeNode)
	}

	child.value = tpe
}

func (n *typeTreeNode) Put(path Ref, tpe types.Type) {
	curr := n
	for _, term := range path {
		c, ok := curr.children.Get(term.Value)

		var child *typeTreeNode
		if !ok {
			child = newTypeTree()
			child.key = term.Value
			curr.children.Put(child.key, child)
		} else {
			child = c.(*typeTreeNode)
		}

		curr = child
	}
	curr.value = tpe
}

func (n *typeTreeNode) Value() types.Type {
	return n.value
}

// selectConstant returns the attribute of the type referred to by the term. If
// the attribute type cannot be determined, nil is returned.
func selectConstant(tpe types.Type, term *Term) types.Type {
	x, err := JSON(term.Value)
	if err == nil {
		return types.Select(tpe, x)
	}
	return nil
}

// selectRef returns the type of the nested attribute referred to by ref. If
// the attribute type cannot be determined, nil is returned. If the ref
// contains vars or refs, then the returned type will be a union of the
// possible types.
func selectRef(tpe types.Type, ref Ref) types.Type {

	if tpe == nil || len(ref) == 0 {
		return tpe
	}

	head, tail := ref[0], ref[1:]

	switch head.Value.(type) {
	case Var, Ref, *Array, Object, Set:
		return selectRef(types.Values(tpe), tail)
	default:
		return selectRef(selectConstant(tpe, head), tail)
	}
}
