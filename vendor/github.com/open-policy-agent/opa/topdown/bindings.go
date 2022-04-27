// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
)

type undo struct {
	k *ast.Term
	u *bindings
}

func (u *undo) Undo() {
	if u == nil {
		// Allow call on zero value of Undo for ease-of-use.
		return
	}
	if u.u == nil {
		// Call on empty unifier undos a no-op unify operation.
		return
	}
	u.u.delete(u.k)
}

type bindings struct {
	id     uint64
	values bindingsArrayHashmap
	instr  *Instrumentation
}

func newBindings(id uint64, instr *Instrumentation) *bindings {
	values := newBindingsArrayHashmap()
	return &bindings{id, values, instr}
}

func (u *bindings) Iter(caller *bindings, iter func(*ast.Term, *ast.Term) error) error {

	var err error

	u.values.Iter(func(k *ast.Term, v value) bool {
		if err != nil {
			return true
		}
		err = iter(k, u.PlugNamespaced(k, caller))

		return false
	})

	return err
}

func (u *bindings) Namespace(x ast.Node, caller *bindings) {
	vis := namespacingVisitor{
		b:      u,
		caller: caller,
	}
	ast.NewGenericVisitor(vis.Visit).Walk(x)
}

func (u *bindings) Plug(a *ast.Term) *ast.Term {
	return u.PlugNamespaced(a, nil)
}

func (u *bindings) PlugNamespaced(a *ast.Term, caller *bindings) *ast.Term {
	if u != nil {
		u.instr.startTimer(evalOpPlug)
		t := u.plugNamespaced(a, caller)
		u.instr.stopTimer(evalOpPlug)
		return t
	}

	return u.plugNamespaced(a, caller)
}

func (u *bindings) plugNamespaced(a *ast.Term, caller *bindings) *ast.Term {
	switch v := a.Value.(type) {
	case ast.Var:
		b, next := u.apply(a)
		if a != b || u != next {
			return next.plugNamespaced(b, caller)
		}
		return u.namespaceVar(b, caller)
	case *ast.Array:
		if a.IsGround() {
			return a
		}
		cpy := *a
		arr := make([]*ast.Term, v.Len())
		for i := 0; i < len(arr); i++ {
			arr[i] = u.plugNamespaced(v.Elem(i), caller)
		}
		cpy.Value = ast.NewArray(arr...)
		return &cpy
	case ast.Object:
		if a.IsGround() {
			return a
		}
		cpy := *a
		cpy.Value, _ = v.Map(func(k, v *ast.Term) (*ast.Term, *ast.Term, error) {
			return u.plugNamespaced(k, caller), u.plugNamespaced(v, caller), nil
		})
		return &cpy
	case ast.Set:
		if a.IsGround() {
			return a
		}
		cpy := *a
		cpy.Value, _ = v.Map(func(x *ast.Term) (*ast.Term, error) {
			return u.plugNamespaced(x, caller), nil
		})
		return &cpy
	case ast.Ref:
		cpy := *a
		ref := make(ast.Ref, len(v))
		for i := 0; i < len(ref); i++ {
			ref[i] = u.plugNamespaced(v[i], caller)
		}
		cpy.Value = ref
		return &cpy
	}
	return a
}

func (u *bindings) bind(a *ast.Term, b *ast.Term, other *bindings, und *undo) {
	u.values.Put(a, value{
		u: other,
		v: b,
	})
	und.k = a
	und.u = u
}

func (u *bindings) apply(a *ast.Term) (*ast.Term, *bindings) {
	// Early exit for non-var terms. Only vars are bound in the binding list,
	// so the lookup below will always fail for non-var terms. In some cases,
	// the lookup may be expensive as it has to hash the term (which for large
	// inputs can be costly).
	_, ok := a.Value.(ast.Var)
	if !ok {
		return a, u
	}
	val, ok := u.get(a)
	if !ok {
		return a, u
	}
	return val.u.apply(val.v)
}

func (u *bindings) delete(v *ast.Term) {
	u.values.Delete(v)
}

func (u *bindings) get(v *ast.Term) (value, bool) {
	if u == nil {
		return value{}, false
	}
	return u.values.Get(v)
}

func (u *bindings) String() string {
	if u == nil {
		return "()"
	}
	var buf []string
	u.values.Iter(func(a *ast.Term, b value) bool {
		buf = append(buf, fmt.Sprintf("%v: %v", a, b))
		return false
	})
	return fmt.Sprintf("({%v}, %v)", strings.Join(buf, ", "), u.id)
}

func (u *bindings) namespaceVar(v *ast.Term, caller *bindings) *ast.Term {
	name, ok := v.Value.(ast.Var)
	if !ok {
		panic("illegal value")
	}
	if caller != nil && caller != u {
		// Root documents (i.e., data, input) should never be namespaced because they
		// are globally unique.
		if !ast.RootDocumentNames.Contains(v) {
			return ast.NewTerm(ast.Var(string(name) + fmt.Sprint(u.id)))
		}
	}
	return v
}

type value struct {
	u *bindings
	v *ast.Term
}

func (v value) String() string {
	return fmt.Sprintf("(%v, %d)", v.v, v.u.id)
}

func (v value) equal(other *value) bool {
	if v.u == other.u {
		return v.v.Equal(other.v)
	}
	return false
}

type namespacingVisitor struct {
	b      *bindings
	caller *bindings
}

func (vis namespacingVisitor) Visit(x interface{}) bool {
	switch x := x.(type) {
	case *ast.ArrayComprehension:
		x.Term = vis.namespaceTerm(x.Term)
		ast.NewGenericVisitor(vis.Visit).Walk(x.Body)
		return true
	case *ast.SetComprehension:
		x.Term = vis.namespaceTerm(x.Term)
		ast.NewGenericVisitor(vis.Visit).Walk(x.Body)
		return true
	case *ast.ObjectComprehension:
		x.Key = vis.namespaceTerm(x.Key)
		x.Value = vis.namespaceTerm(x.Value)
		ast.NewGenericVisitor(vis.Visit).Walk(x.Body)
		return true
	case *ast.Expr:
		switch terms := x.Terms.(type) {
		case []*ast.Term:
			for i := 1; i < len(terms); i++ {
				terms[i] = vis.namespaceTerm(terms[i])
			}
		case *ast.Term:
			x.Terms = vis.namespaceTerm(terms)
		}
		for _, w := range x.With {
			w.Target = vis.namespaceTerm(w.Target)
			w.Value = vis.namespaceTerm(w.Value)
		}
	}
	return false
}

func (vis namespacingVisitor) namespaceTerm(a *ast.Term) *ast.Term {
	switch v := a.Value.(type) {
	case ast.Var:
		return vis.b.namespaceVar(a, vis.caller)
	case *ast.Array:
		if a.IsGround() {
			return a
		}
		cpy := *a
		arr := make([]*ast.Term, v.Len())
		for i := 0; i < len(arr); i++ {
			arr[i] = vis.namespaceTerm(v.Elem(i))
		}
		cpy.Value = ast.NewArray(arr...)
		return &cpy
	case ast.Object:
		if a.IsGround() {
			return a
		}
		cpy := *a
		cpy.Value, _ = v.Map(func(k, v *ast.Term) (*ast.Term, *ast.Term, error) {
			return vis.namespaceTerm(k), vis.namespaceTerm(v), nil
		})
		return &cpy
	case ast.Set:
		if a.IsGround() {
			return a
		}
		cpy := *a
		cpy.Value, _ = v.Map(func(x *ast.Term) (*ast.Term, error) {
			return vis.namespaceTerm(x), nil
		})
		return &cpy
	case ast.Ref:
		cpy := *a
		ref := make(ast.Ref, len(v))
		for i := 0; i < len(ref); i++ {
			ref[i] = vis.namespaceTerm(v[i])
		}
		cpy.Value = ref
		return &cpy
	}
	return a
}

const maxLinearScan = 16

// bindingsArrayHashMap uses an array with linear scan instead
// of a hash map for smaller # of entries. Hash maps start to
// show off their performance advantage only after 16 keys.
type bindingsArrayHashmap struct {
	n int // Entries in the array.
	a *[maxLinearScan]bindingArrayKeyValue
	m map[ast.Var]bindingArrayKeyValue
}

type bindingArrayKeyValue struct {
	key   *ast.Term
	value value
}

func newBindingsArrayHashmap() bindingsArrayHashmap {
	return bindingsArrayHashmap{}
}

func (b *bindingsArrayHashmap) Put(key *ast.Term, value value) {
	if b.m == nil {
		if b.a == nil {
			b.a = new([maxLinearScan]bindingArrayKeyValue)
		} else if i := b.find(key); i >= 0 {
			(*b.a)[i].value = value
			return
		}

		if b.n < maxLinearScan {
			(*b.a)[b.n] = bindingArrayKeyValue{key, value}
			b.n++
			return
		}

		// Array is full, revert to using the hash map instead.

		b.m = make(map[ast.Var]bindingArrayKeyValue, maxLinearScan+1)
		for _, kv := range *b.a {
			b.m[kv.key.Value.(ast.Var)] = bindingArrayKeyValue{kv.key, kv.value}
		}
		b.m[key.Value.(ast.Var)] = bindingArrayKeyValue{key, value}

		b.n = 0
		return
	}

	b.m[key.Value.(ast.Var)] = bindingArrayKeyValue{key, value}
}

func (b *bindingsArrayHashmap) Get(key *ast.Term) (value, bool) {
	if b.m == nil {
		if i := b.find(key); i >= 0 {
			return (*b.a)[i].value, true
		}

		return value{}, false
	}

	v, ok := b.m[key.Value.(ast.Var)]
	if ok {
		return v.value, true
	}

	return value{}, false
}

func (b *bindingsArrayHashmap) Delete(key *ast.Term) {
	if b.m == nil {
		if i := b.find(key); i >= 0 {
			n := b.n - 1
			if i < n {
				(*b.a)[i] = (*b.a)[n]
			}

			b.n = n
		}
		return
	}

	delete(b.m, key.Value.(ast.Var))
}

func (b *bindingsArrayHashmap) Iter(f func(k *ast.Term, v value) bool) {
	if b.m == nil {
		for i := 0; i < b.n; i++ {
			if f((*b.a)[i].key, (*b.a)[i].value) {
				return
			}
		}
		return
	}

	for _, v := range b.m {
		if f(v.key, v.value) {
			return
		}
	}
}

func (b *bindingsArrayHashmap) find(key *ast.Term) int {
	v := key.Value.(ast.Var)
	for i := 0; i < b.n; i++ {
		if (*b.a)[i].key.Value.(ast.Var) == v {
			return i
		}
	}

	return -1
}
