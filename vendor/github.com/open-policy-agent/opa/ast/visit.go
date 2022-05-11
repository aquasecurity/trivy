// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

// Visitor defines the interface for iterating AST elements. The Visit function
// can return a Visitor w which will be used to visit the children of the AST
// element v. If the Visit function returns nil, the children will not be
// visited. This is deprecated.
type Visitor interface {
	Visit(v interface{}) (w Visitor)
}

// BeforeAndAfterVisitor wraps Visitor to provide hooks for being called before
// and after the AST has been visited. This is deprecated.
type BeforeAndAfterVisitor interface {
	Visitor
	Before(x interface{})
	After(x interface{})
}

// Walk iterates the AST by calling the Visit function on the Visitor
// v for x before recursing. This is deprecated.
func Walk(v Visitor, x interface{}) {
	if bav, ok := v.(BeforeAndAfterVisitor); !ok {
		walk(v, x)
	} else {
		bav.Before(x)
		defer bav.After(x)
		walk(bav, x)
	}
}

// WalkBeforeAndAfter iterates the AST by calling the Visit function on the
// Visitor v for x before recursing. This is deprecated.
func WalkBeforeAndAfter(v BeforeAndAfterVisitor, x interface{}) {
	Walk(v, x)
}

func walk(v Visitor, x interface{}) {
	w := v.Visit(x)
	if w == nil {
		return
	}
	switch x := x.(type) {
	case *Module:
		Walk(w, x.Package)
		for _, i := range x.Imports {
			Walk(w, i)
		}
		for _, r := range x.Rules {
			Walk(w, r)
		}
		for _, a := range x.Annotations {
			Walk(w, a)
		}
		for _, c := range x.Comments {
			Walk(w, c)
		}
	case *Package:
		Walk(w, x.Path)
	case *Import:
		Walk(w, x.Path)
		Walk(w, x.Alias)
	case *Rule:
		Walk(w, x.Head)
		Walk(w, x.Body)
		if x.Else != nil {
			Walk(w, x.Else)
		}
	case *Head:
		Walk(w, x.Name)
		Walk(w, x.Args)
		if x.Key != nil {
			Walk(w, x.Key)
		}
		if x.Value != nil {
			Walk(w, x.Value)
		}
	case Body:
		for _, e := range x {
			Walk(w, e)
		}
	case Args:
		for _, t := range x {
			Walk(w, t)
		}
	case *Expr:
		switch ts := x.Terms.(type) {
		case *Term, *SomeDecl, *Every:
			Walk(w, ts)
		case []*Term:
			for _, t := range ts {
				Walk(w, t)
			}
		}
		for i := range x.With {
			Walk(w, x.With[i])
		}
	case *With:
		Walk(w, x.Target)
		Walk(w, x.Value)
	case *Term:
		Walk(w, x.Value)
	case Ref:
		for _, t := range x {
			Walk(w, t)
		}
	case *object:
		x.Foreach(func(k, vv *Term) {
			Walk(w, k)
			Walk(w, vv)
		})
	case *Array:
		x.Foreach(func(t *Term) {
			Walk(w, t)
		})
	case Set:
		x.Foreach(func(t *Term) {
			Walk(w, t)
		})
	case *ArrayComprehension:
		Walk(w, x.Term)
		Walk(w, x.Body)
	case *ObjectComprehension:
		Walk(w, x.Key)
		Walk(w, x.Value)
		Walk(w, x.Body)
	case *SetComprehension:
		Walk(w, x.Term)
		Walk(w, x.Body)
	case Call:
		for _, t := range x {
			Walk(w, t)
		}
	case *Every:
		if x.Key != nil {
			Walk(w, x.Key)
		}
		Walk(w, x.Value)
		Walk(w, x.Domain)
		Walk(w, x.Body)
	}
}

// WalkVars calls the function f on all vars under x. If the function f
// returns true, AST nodes under the last node will not be visited.
func WalkVars(x interface{}, f func(Var) bool) {
	vis := &GenericVisitor{func(x interface{}) bool {
		if v, ok := x.(Var); ok {
			return f(v)
		}
		return false
	}}
	vis.Walk(x)
}

// WalkClosures calls the function f on all closures under x. If the function f
// returns true, AST nodes under the last node will not be visited.
func WalkClosures(x interface{}, f func(interface{}) bool) {
	vis := &GenericVisitor{func(x interface{}) bool {
		switch x := x.(type) {
		case *ArrayComprehension, *ObjectComprehension, *SetComprehension, *Every:
			return f(x)
		}
		return false
	}}
	vis.Walk(x)
}

// WalkRefs calls the function f on all references under x. If the function f
// returns true, AST nodes under the last node will not be visited.
func WalkRefs(x interface{}, f func(Ref) bool) {
	vis := &GenericVisitor{func(x interface{}) bool {
		if r, ok := x.(Ref); ok {
			return f(r)
		}
		return false
	}}
	vis.Walk(x)
}

// WalkTerms calls the function f on all terms under x. If the function f
// returns true, AST nodes under the last node will not be visited.
func WalkTerms(x interface{}, f func(*Term) bool) {
	vis := &GenericVisitor{func(x interface{}) bool {
		if term, ok := x.(*Term); ok {
			return f(term)
		}
		return false
	}}
	vis.Walk(x)
}

// WalkWiths calls the function f on all with modifiers under x. If the function f
// returns true, AST nodes under the last node will not be visited.
func WalkWiths(x interface{}, f func(*With) bool) {
	vis := &GenericVisitor{func(x interface{}) bool {
		if w, ok := x.(*With); ok {
			return f(w)
		}
		return false
	}}
	vis.Walk(x)
}

// WalkExprs calls the function f on all expressions under x. If the function f
// returns true, AST nodes under the last node will not be visited.
func WalkExprs(x interface{}, f func(*Expr) bool) {
	vis := &GenericVisitor{func(x interface{}) bool {
		if r, ok := x.(*Expr); ok {
			return f(r)
		}
		return false
	}}
	vis.Walk(x)
}

// WalkBodies calls the function f on all bodies under x. If the function f
// returns true, AST nodes under the last node will not be visited.
func WalkBodies(x interface{}, f func(Body) bool) {
	vis := &GenericVisitor{func(x interface{}) bool {
		if b, ok := x.(Body); ok {
			return f(b)
		}
		return false
	}}
	vis.Walk(x)
}

// WalkRules calls the function f on all rules under x. If the function f
// returns true, AST nodes under the last node will not be visited.
func WalkRules(x interface{}, f func(*Rule) bool) {
	vis := &GenericVisitor{func(x interface{}) bool {
		if r, ok := x.(*Rule); ok {
			stop := f(r)
			// NOTE(tsandall): since rules cannot be embedded inside of queries
			// we can stop early if there is no else block.
			if stop || r.Else == nil {
				return true
			}
		}
		return false
	}}
	vis.Walk(x)
}

// WalkNodes calls the function f on all nodes under x. If the function f
// returns true, AST nodes under the last node will not be visited.
func WalkNodes(x interface{}, f func(Node) bool) {
	vis := &GenericVisitor{func(x interface{}) bool {
		if n, ok := x.(Node); ok {
			return f(n)
		}
		return false
	}}
	vis.Walk(x)
}

// GenericVisitor provides a utility to walk over AST nodes using a
// closure. If the closure returns true, the visitor will not walk
// over AST nodes under x.
type GenericVisitor struct {
	f func(x interface{}) bool
}

// NewGenericVisitor returns a new GenericVisitor that will invoke the function
// f on AST nodes.
func NewGenericVisitor(f func(x interface{}) bool) *GenericVisitor {
	return &GenericVisitor{f}
}

// Walk iterates the AST by calling the function f on the
// GenericVisitor before recursing. Contrary to the generic Walk, this
// does not require allocating the visitor from heap.
func (vis *GenericVisitor) Walk(x interface{}) {
	if vis.f(x) {
		return
	}

	switch x := x.(type) {
	case *Module:
		vis.Walk(x.Package)
		for _, i := range x.Imports {
			vis.Walk(i)
		}
		for _, r := range x.Rules {
			vis.Walk(r)
		}
		for _, a := range x.Annotations {
			vis.Walk(a)
		}
		for _, c := range x.Comments {
			vis.Walk(c)
		}
	case *Package:
		vis.Walk(x.Path)
	case *Import:
		vis.Walk(x.Path)
		vis.Walk(x.Alias)
	case *Rule:
		vis.Walk(x.Head)
		vis.Walk(x.Body)
		if x.Else != nil {
			vis.Walk(x.Else)
		}
	case *Head:
		vis.Walk(x.Name)
		vis.Walk(x.Args)
		if x.Key != nil {
			vis.Walk(x.Key)
		}
		if x.Value != nil {
			vis.Walk(x.Value)
		}
	case Body:
		for _, e := range x {
			vis.Walk(e)
		}
	case Args:
		for _, t := range x {
			vis.Walk(t)
		}
	case *Expr:
		switch ts := x.Terms.(type) {
		case *Term, *SomeDecl, *Every:
			vis.Walk(ts)
		case []*Term:
			for _, t := range ts {
				vis.Walk(t)
			}
		}
		for i := range x.With {
			vis.Walk(x.With[i])
		}
	case *With:
		vis.Walk(x.Target)
		vis.Walk(x.Value)
	case *Term:
		vis.Walk(x.Value)
	case Ref:
		for _, t := range x {
			vis.Walk(t)
		}
	case *object:
		x.Foreach(func(k, v *Term) {
			vis.Walk(k)
			vis.Walk(x.Get(k))
		})
	case *Array:
		x.Foreach(func(t *Term) {
			vis.Walk(t)
		})
	case Set:
		for _, t := range x.Slice() {
			vis.Walk(t)
		}
	case *ArrayComprehension:
		vis.Walk(x.Term)
		vis.Walk(x.Body)
	case *ObjectComprehension:
		vis.Walk(x.Key)
		vis.Walk(x.Value)
		vis.Walk(x.Body)
	case *SetComprehension:
		vis.Walk(x.Term)
		vis.Walk(x.Body)
	case Call:
		for _, t := range x {
			vis.Walk(t)
		}
	case *Every:
		if x.Key != nil {
			vis.Walk(x.Key)
		}
		vis.Walk(x.Value)
		vis.Walk(x.Domain)
		vis.Walk(x.Body)
	}
}

// BeforeAfterVisitor provides a utility to walk over AST nodes using
// closures. If the before closure returns true, the visitor will not
// walk over AST nodes under x. The after closure is invoked always
// after visiting a node.
type BeforeAfterVisitor struct {
	before func(x interface{}) bool
	after  func(x interface{})
}

// NewBeforeAfterVisitor returns a new BeforeAndAfterVisitor that
// will invoke the functions before and after AST nodes.
func NewBeforeAfterVisitor(before func(x interface{}) bool, after func(x interface{})) *BeforeAfterVisitor {
	return &BeforeAfterVisitor{before, after}
}

// Walk iterates the AST by calling the functions on the
// BeforeAndAfterVisitor before and after recursing. Contrary to the
// generic Walk, this does not require allocating the visitor from
// heap.
func (vis *BeforeAfterVisitor) Walk(x interface{}) {
	defer vis.after(x)
	if vis.before(x) {
		return
	}

	switch x := x.(type) {
	case *Module:
		vis.Walk(x.Package)
		for _, i := range x.Imports {
			vis.Walk(i)
		}
		for _, r := range x.Rules {
			vis.Walk(r)
		}
		for _, a := range x.Annotations {
			vis.Walk(a)
		}
		for _, c := range x.Comments {
			vis.Walk(c)
		}
	case *Package:
		vis.Walk(x.Path)
	case *Import:
		vis.Walk(x.Path)
		vis.Walk(x.Alias)
	case *Rule:
		vis.Walk(x.Head)
		vis.Walk(x.Body)
		if x.Else != nil {
			vis.Walk(x.Else)
		}
	case *Head:
		vis.Walk(x.Name)
		vis.Walk(x.Args)
		if x.Key != nil {
			vis.Walk(x.Key)
		}
		if x.Value != nil {
			vis.Walk(x.Value)
		}
	case Body:
		for _, e := range x {
			vis.Walk(e)
		}
	case Args:
		for _, t := range x {
			vis.Walk(t)
		}
	case *Expr:
		switch ts := x.Terms.(type) {
		case *Term, *SomeDecl, *Every:
			vis.Walk(ts)
		case []*Term:
			for _, t := range ts {
				vis.Walk(t)
			}
		}
		for i := range x.With {
			vis.Walk(x.With[i])
		}
	case *With:
		vis.Walk(x.Target)
		vis.Walk(x.Value)
	case *Term:
		vis.Walk(x.Value)
	case Ref:
		for _, t := range x {
			vis.Walk(t)
		}
	case *object:
		x.Foreach(func(k, v *Term) {
			vis.Walk(k)
			vis.Walk(x.Get(k))
		})
	case *Array:
		x.Foreach(func(t *Term) {
			vis.Walk(t)
		})
	case Set:
		for _, t := range x.Slice() {
			vis.Walk(t)
		}
	case *ArrayComprehension:
		vis.Walk(x.Term)
		vis.Walk(x.Body)
	case *ObjectComprehension:
		vis.Walk(x.Key)
		vis.Walk(x.Value)
		vis.Walk(x.Body)
	case *SetComprehension:
		vis.Walk(x.Term)
		vis.Walk(x.Body)
	case Call:
		for _, t := range x {
			vis.Walk(t)
		}
	case *Every:
		if x.Key != nil {
			vis.Walk(x.Key)
		}
		vis.Walk(x.Value)
		vis.Walk(x.Domain)
		vis.Walk(x.Body)
	}
}

// VarVisitor walks AST nodes under a given node and collects all encountered
// variables. The collected variables can be controlled by specifying
// VarVisitorParams when creating the visitor.
type VarVisitor struct {
	params VarVisitorParams
	vars   VarSet
}

// VarVisitorParams contains settings for a VarVisitor.
type VarVisitorParams struct {
	SkipRefHead     bool
	SkipRefCallHead bool
	SkipObjectKeys  bool
	SkipClosures    bool
	SkipWithTarget  bool
	SkipSets        bool
}

// NewVarVisitor returns a new VarVisitor object.
func NewVarVisitor() *VarVisitor {
	return &VarVisitor{
		vars: NewVarSet(),
	}
}

// WithParams sets the parameters in params on vis.
func (vis *VarVisitor) WithParams(params VarVisitorParams) *VarVisitor {
	vis.params = params
	return vis
}

// Vars returns a VarSet that contains collected vars.
func (vis *VarVisitor) Vars() VarSet {
	return vis.vars
}

// visit determines if the VarVisitor will recurse into x: if it returns `true`,
// the visitor will _skip_ that branch of the AST
func (vis *VarVisitor) visit(v interface{}) bool {
	if vis.params.SkipObjectKeys {
		if o, ok := v.(Object); ok {
			o.Foreach(func(k, v *Term) {
				vis.Walk(v)
			})
			return true
		}
	}
	if vis.params.SkipRefHead {
		if r, ok := v.(Ref); ok {
			for _, t := range r[1:] {
				vis.Walk(t)
			}
			return true
		}
	}
	if vis.params.SkipClosures {
		switch v := v.(type) {
		case *ArrayComprehension, *ObjectComprehension, *SetComprehension:
			return true
		case *Expr:
			if ev, ok := v.Terms.(*Every); ok {
				vis.Walk(ev.Domain)
				// We're _not_ walking ev.Body -- that's the closure here
				return true
			}
		}
	}
	if vis.params.SkipWithTarget {
		if v, ok := v.(*With); ok {
			vis.Walk(v.Value)
			return true
		}
	}
	if vis.params.SkipSets {
		if _, ok := v.(Set); ok {
			return true
		}
	}
	if vis.params.SkipRefCallHead {
		switch v := v.(type) {
		case *Expr:
			if terms, ok := v.Terms.([]*Term); ok {
				for _, t := range terms[0].Value.(Ref)[1:] {
					vis.Walk(t)
				}
				for i := 1; i < len(terms); i++ {
					vis.Walk(terms[i])
				}
				for _, w := range v.With {
					vis.Walk(w)
				}
				return true
			}
		case Call:
			operator := v[0].Value.(Ref)
			for i := 1; i < len(operator); i++ {
				vis.Walk(operator[i])
			}
			for i := 1; i < len(v); i++ {
				vis.Walk(v[i])
			}
			return true
		case *With:
			if ref, ok := v.Target.Value.(Ref); ok {
				for _, t := range ref[1:] {
					vis.Walk(t)
				}
			}
			if ref, ok := v.Value.Value.(Ref); ok {
				for _, t := range ref[1:] {
					vis.Walk(t)
				}
			} else {
				vis.Walk(v.Value)
			}
			return true
		}
	}
	if v, ok := v.(Var); ok {
		vis.vars.Add(v)
	}
	return false
}

// Walk iterates the AST by calling the function f on the
// GenericVisitor before recursing. Contrary to the generic Walk, this
// does not require allocating the visitor from heap.
func (vis *VarVisitor) Walk(x interface{}) {
	if vis.visit(x) {
		return
	}

	switch x := x.(type) {
	case *Module:
		vis.Walk(x.Package)
		for _, i := range x.Imports {
			vis.Walk(i)
		}
		for _, r := range x.Rules {
			vis.Walk(r)
		}
		for _, c := range x.Comments {
			vis.Walk(c)
		}
	case *Package:
		vis.Walk(x.Path)
	case *Import:
		vis.Walk(x.Path)
		vis.Walk(x.Alias)
	case *Rule:
		vis.Walk(x.Head)
		vis.Walk(x.Body)
		if x.Else != nil {
			vis.Walk(x.Else)
		}
	case *Head:
		vis.Walk(x.Name)
		vis.Walk(x.Args)
		if x.Key != nil {
			vis.Walk(x.Key)
		}
		if x.Value != nil {
			vis.Walk(x.Value)
		}
	case Body:
		for _, e := range x {
			vis.Walk(e)
		}
	case Args:
		for _, t := range x {
			vis.Walk(t)
		}
	case *Expr:
		switch ts := x.Terms.(type) {
		case *Term, *SomeDecl, *Every:
			vis.Walk(ts)
		case []*Term:
			for _, t := range ts {
				vis.Walk(t)
			}
		}
		for i := range x.With {
			vis.Walk(x.With[i])
		}
	case *With:
		vis.Walk(x.Target)
		vis.Walk(x.Value)
	case *Term:
		vis.Walk(x.Value)
	case Ref:
		for _, t := range x {
			vis.Walk(t)
		}
	case *object:
		x.Foreach(func(k, v *Term) {
			vis.Walk(k)
			vis.Walk(x.Get(k))
		})
	case *Array:
		x.Foreach(func(t *Term) {
			vis.Walk(t)
		})
	case Set:
		for _, t := range x.Slice() {
			vis.Walk(t)
		}
	case *ArrayComprehension:
		vis.Walk(x.Term)
		vis.Walk(x.Body)
	case *ObjectComprehension:
		vis.Walk(x.Key)
		vis.Walk(x.Value)
		vis.Walk(x.Body)
	case *SetComprehension:
		vis.Walk(x.Term)
		vis.Walk(x.Body)
	case Call:
		for _, t := range x {
			vis.Walk(t)
		}
	case *Every:
		if x.Key != nil {
			vis.Walk(x.Key)
		}
		vis.Walk(x.Value)
		vis.Walk(x.Domain)
		vis.Walk(x.Body)
	}
}
