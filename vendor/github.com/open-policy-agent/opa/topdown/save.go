package topdown

import (
	"container/list"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
)

// saveSet contains a stack of terms that are considered 'unknown' during
// partial evaluation. Only var and ref terms (rooted at one of the root
// documents) can be added to the save set. Vars added to the save set are
// namespaced by the binding list they are added with. This means the save set
// can be shared across queries.
type saveSet struct {
	instr *Instrumentation
	l     *list.List
}

func newSaveSet(ts []*ast.Term, b *bindings, instr *Instrumentation) *saveSet {
	ss := &saveSet{
		l:     list.New(),
		instr: instr,
	}
	ss.Push(ts, b)
	return ss
}

func (ss *saveSet) Push(ts []*ast.Term, b *bindings) {
	ss.l.PushBack(newSaveSetElem(ts, b))
}

func (ss *saveSet) Pop() {
	ss.l.Remove(ss.l.Back())
}

// Contains returns true if the term t is contained in the save set. Non-var and
// non-ref terms are never contained. Ref terms are contained if they share a
// prefix with a ref that was added (in either direction).
func (ss *saveSet) Contains(t *ast.Term, b *bindings) bool {
	if ss != nil {
		ss.instr.startTimer(partialOpSaveSetContains)
		ret := ss.contains(t, b)
		ss.instr.stopTimer(partialOpSaveSetContains)
		return ret
	}
	return false
}

func (ss *saveSet) contains(t *ast.Term, b *bindings) bool {
	for el := ss.l.Back(); el != nil; el = el.Prev() {
		if el.Value.(*saveSetElem).Contains(t, b) {
			return true
		}
	}
	return false
}

// ContainsRecursive returns true if the term t is or contains a term that is
// contained in the save set. This function will close over the binding list
// when it encounters vars.
func (ss *saveSet) ContainsRecursive(t *ast.Term, b *bindings) bool {
	if ss != nil {
		ss.instr.startTimer(partialOpSaveSetContainsRec)
		ret := ss.containsrec(t, b)
		ss.instr.stopTimer(partialOpSaveSetContainsRec)
		return ret
	}
	return false
}

func (ss *saveSet) containsrec(t *ast.Term, b *bindings) bool {
	var found bool
	ast.WalkTerms(t, func(x *ast.Term) bool {
		if _, ok := x.Value.(ast.Var); ok {
			x1, b1 := b.apply(x)
			if x1 != x || b1 != b {
				if ss.containsrec(x1, b1) {
					found = true
				}
			} else if ss.contains(x1, b1) {
				found = true
			}
		}
		return found
	})
	return found
}

func (ss *saveSet) Vars(caller *bindings) ast.VarSet {
	result := ast.NewVarSet()
	for x := ss.l.Front(); x != nil; x = x.Next() {
		elem := x.Value.(*saveSetElem)
		for _, v := range elem.vars {
			if v, ok := elem.b.PlugNamespaced(v, caller).Value.(ast.Var); ok {
				result.Add(v)
			}
		}
	}
	return result
}

func (ss *saveSet) String() string {
	var buf []string

	for x := ss.l.Front(); x != nil; x = x.Next() {
		buf = append(buf, x.Value.(*saveSetElem).String())
	}

	return "(" + strings.Join(buf, " ") + ")"
}

type saveSetElem struct {
	refs []ast.Ref
	vars []*ast.Term
	b    *bindings
}

func newSaveSetElem(ts []*ast.Term, b *bindings) *saveSetElem {

	var refs []ast.Ref
	var vars []*ast.Term

	for _, t := range ts {
		switch v := t.Value.(type) {
		case ast.Var:
			vars = append(vars, t)
		case ast.Ref:
			refs = append(refs, v)
		default:
			panic("illegal value")
		}
	}

	return &saveSetElem{
		b:    b,
		vars: vars,
		refs: refs,
	}
}

func (sse *saveSetElem) Contains(t *ast.Term, b *bindings) bool {
	switch other := t.Value.(type) {
	case ast.Var:
		return sse.containsVar(t, b)
	case ast.Ref:
		for _, ref := range sse.refs {
			if ref.HasPrefix(other) || other.HasPrefix(ref) {
				return true
			}
		}
		return sse.containsVar(other[0], b)
	}
	return false
}

func (sse *saveSetElem) String() string {
	return fmt.Sprintf("(refs: %v, vars: %v, b: %v)", sse.refs, sse.vars, sse.b)
}

func (sse *saveSetElem) containsVar(t *ast.Term, b *bindings) bool {
	if b == sse.b {
		for _, v := range sse.vars {
			if v.Equal(t) {
				return true
			}
		}
	}
	return false
}

// saveStack contains a stack of queries that represent the result of partial
// evaluation. When partial evaluation completes, the top of the stack
// represents a complete, partially evaluated query that can be saved and
// evaluated later.
//
// The result is stored in a stack so that partial evaluation of a query can be
// paused and then resumed in cases where different queries make up the result
// of partial evaluation, such as when a rule with a default clause is
// partially evaluated. In this case, the partially evaluated rule will be
// output in the support module.
type saveStack struct {
	Stack []saveStackQuery
}

func newSaveStack() *saveStack {
	return &saveStack{
		Stack: []saveStackQuery{
			{},
		},
	}
}

func (s *saveStack) PushQuery(query saveStackQuery) {
	s.Stack = append(s.Stack, query)
}

func (s *saveStack) PopQuery() saveStackQuery {
	last := s.Stack[len(s.Stack)-1]
	s.Stack = s.Stack[:len(s.Stack)-1]
	return last
}

func (s *saveStack) Peek() saveStackQuery {
	return s.Stack[len(s.Stack)-1]
}

func (s *saveStack) Push(expr *ast.Expr, b1 *bindings, b2 *bindings) {
	idx := len(s.Stack) - 1
	s.Stack[idx] = append(s.Stack[idx], saveStackElem{expr, b1, b2})
}

func (s *saveStack) Pop() {
	idx := len(s.Stack) - 1
	query := s.Stack[idx]
	s.Stack[idx] = query[:len(query)-1]
}

type saveStackQuery []saveStackElem

func (s saveStackQuery) Plug(b *bindings) ast.Body {
	if len(s) == 0 {
		return ast.NewBody(ast.NewExpr(ast.BooleanTerm(true)))
	}
	result := make(ast.Body, len(s))
	for i := range s {
		expr := s[i].Plug(b)
		result.Set(expr, i)
	}
	return result
}

type saveStackElem struct {
	Expr *ast.Expr
	B1   *bindings
	B2   *bindings
}

func (e saveStackElem) Plug(caller *bindings) *ast.Expr {
	if e.B1 == nil && e.B2 == nil {
		return e.Expr
	}
	expr := e.Expr.Copy()
	switch terms := expr.Terms.(type) {
	case []*ast.Term:
		if expr.IsEquality() {
			terms[1] = e.B1.PlugNamespaced(terms[1], caller)
			terms[2] = e.B2.PlugNamespaced(terms[2], caller)
		} else {
			for i := 1; i < len(terms); i++ {
				terms[i] = e.B1.PlugNamespaced(terms[i], caller)
			}
		}
	case *ast.Term:
		expr.Terms = e.B1.PlugNamespaced(terms, caller)
	}
	for i := range expr.With {
		expr.With[i].Value = e.B1.PlugNamespaced(expr.With[i].Value, caller)
	}
	return expr
}

// saveSupport contains additional partially evaluated policies that are part
// of the output of partial evaluation.
//
// The support structure is accumulated as partial evaluation runs and then
// considered complete once partial evaluation finishes (but not before). This
// differs from partially evaluated queries which are considered complete as
// soon as each one finishes.
type saveSupport struct {
	modules map[string]*ast.Module
}

func newSaveSupport() *saveSupport {
	return &saveSupport{
		modules: map[string]*ast.Module{},
	}
}

func (s *saveSupport) List() []*ast.Module {
	result := make([]*ast.Module, 0, len(s.modules))
	for _, module := range s.modules {
		result = append(result, module)
	}
	return result
}

func (s *saveSupport) Exists(path ast.Ref) bool {
	k := path[:len(path)-1].String()
	module, ok := s.modules[k]
	if !ok {
		return false
	}
	name := ast.Var(path[len(path)-1].Value.(ast.String))
	for _, rule := range module.Rules {
		if rule.Head.Name.Equal(name) {
			return true
		}
	}
	return false
}

func (s *saveSupport) Insert(path ast.Ref, rule *ast.Rule) {
	pkg := path[:len(path)-1]
	k := pkg.String()
	module, ok := s.modules[k]
	if !ok {
		module = &ast.Module{
			Package: &ast.Package{
				Path: pkg,
			},
		}
		s.modules[k] = module
	}
	rule.Module = module
	module.Rules = append(module.Rules, rule)
}

// saveRequired returns true if the statement x will result in some expressions
// being saved. This check allows the evaluator to evaluate statements
// completely during partial evaluation as long as they do not depend on any
// kind of unknown value or statements that would generate saves.
func saveRequired(c *ast.Compiler, ic *inliningControl, icIgnoreInternal bool, ss *saveSet, b *bindings, x interface{}, rec bool) bool {

	var found bool

	vis := ast.NewGenericVisitor(func(node interface{}) bool {
		if found {
			return found
		}
		switch node := node.(type) {
		case *ast.Expr:
			found = len(node.With) > 0 || ignoreExprDuringPartial(node)
		case *ast.Term:
			switch v := node.Value.(type) {
			case ast.Var:
				// Variables only need to be tested in the node from call site
				// because once traversal recurses into a rule existing unknown
				// variables are out-of-scope.
				if !rec && ss.ContainsRecursive(node, b) {
					found = true
				}
			case ast.Ref:
				if ss.Contains(node, b) {
					found = true
				} else if ic.Disabled(v.ConstantPrefix(), icIgnoreInternal) {
					found = true
				} else {
					for _, rule := range c.GetRulesDynamicWithOpts(v, ast.RulesOptions{IncludeHiddenModules: false}) {
						if saveRequired(c, ic, icIgnoreInternal, ss, b, rule, true) {
							found = true
							break
						}
					}
				}
			}
		}
		return found
	})

	vis.Walk(x)

	return found
}

func ignoreExprDuringPartial(expr *ast.Expr) bool {
	if !expr.IsCall() {
		return false
	}

	bi, ok := ast.BuiltinMap[expr.Operator().String()]

	return ok && ignoreDuringPartial(bi)
}

func ignoreDuringPartial(bi *ast.Builtin) bool {
	for _, ignore := range ast.IgnoreDuringPartialEval {
		if bi == ignore {
			return true
		}
	}
	return false
}

type inliningControl struct {
	shallow bool
	disable []disableInliningFrame
}

type disableInliningFrame struct {
	internal bool
	refs     []ast.Ref
}

func (i *inliningControl) PushDisable(refs []ast.Ref, internal bool) {
	if i == nil {
		return
	}
	i.disable = append(i.disable, disableInliningFrame{
		internal: internal,
		refs:     refs,
	})
}

func (i *inliningControl) PopDisable() {
	if i == nil {
		return
	}
	i.disable = i.disable[:len(i.disable)-1]
}

func (i *inliningControl) Disabled(ref ast.Ref, ignoreInternal bool) bool {
	if i == nil {
		return false
	}
	for _, frame := range i.disable {
		if !frame.internal || !ignoreInternal {
			for _, other := range frame.refs {
				if other.HasPrefix(ref) || ref.HasPrefix(other) {
					return true
				}
			}
		}
	}
	return false
}
