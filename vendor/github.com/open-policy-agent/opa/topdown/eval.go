package topdown

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/topdown/cache"
	"github.com/open-policy-agent/opa/topdown/copypropagation"
	"github.com/open-policy-agent/opa/topdown/print"
	"github.com/open-policy-agent/opa/tracing"
)

type evalIterator func(*eval) error

type unifyIterator func() error

type queryIDFactory struct {
	curr uint64
}

// Note: The first call to Next() returns 0.
func (f *queryIDFactory) Next() uint64 {
	curr := f.curr
	f.curr++
	return curr
}

type builtinErrors struct {
	errs []error
}

// earlyExitError is used to abort iteration where early exit is possible
type earlyExitError struct {
	prev error
	e    *eval
}

func (ee *earlyExitError) Error() string {
	return fmt.Sprintf("%v: early exit", ee.e.query)
}

type eval struct {
	ctx                    context.Context
	metrics                metrics.Metrics
	seed                   io.Reader
	time                   *ast.Term
	queryID                uint64
	queryIDFact            *queryIDFactory
	parent                 *eval
	caller                 *eval
	cancel                 Cancel
	query                  ast.Body
	queryCompiler          ast.QueryCompiler
	index                  int
	indexing               bool
	earlyExit              bool
	bindings               *bindings
	store                  storage.Store
	baseCache              *baseCache
	txn                    storage.Transaction
	compiler               *ast.Compiler
	input                  *ast.Term
	data                   *ast.Term
	external               *resolverTrie
	targetStack            *refStack
	tracers                []QueryTracer
	traceEnabled           bool
	plugTraceVars          bool
	instr                  *Instrumentation
	builtins               map[string]*Builtin
	builtinCache           builtins.Cache
	virtualCache           *virtualCache
	comprehensionCache     *comprehensionCache
	interQueryBuiltinCache cache.InterQueryCache
	saveSet                *saveSet
	saveStack              *saveStack
	saveSupport            *saveSupport
	saveNamespace          *ast.Term
	skipSaveNamespace      bool
	inliningControl        *inliningControl
	genvarprefix           string
	genvarid               int
	runtime                *ast.Term
	builtinErrors          *builtinErrors
	printHook              print.Hook
	tracingOpts            tracing.Options
	findOne                bool
}

func (e *eval) Run(iter evalIterator) error {
	e.traceEnter(e.query)
	return e.eval(func(e *eval) error {
		e.traceExit(e.query)
		err := iter(e)
		e.traceRedo(e.query)
		return err
	})
}

func (e *eval) String() string {
	s := strings.Builder{}
	e.string(&s)
	return s.String()
}

func (e *eval) string(s *strings.Builder) {
	fmt.Fprintf(s, "<query: %v index: %d findOne: %v", e.query, e.index, e.findOne)
	if e.parent != nil {
		s.WriteRune(' ')
		e.parent.string(s)
	}
	s.WriteRune('>')
}

func (e *eval) builtinFunc(name string) (*ast.Builtin, BuiltinFunc, bool) {
	decl, ok := ast.BuiltinMap[name]
	if ok {
		f, ok := builtinFunctions[name]
		if ok {
			return decl, f, true
		}
	} else {
		bi, ok := e.builtins[name]
		if ok {
			return bi.Decl, bi.Func, true
		}
	}
	return nil, nil, false
}

func (e *eval) closure(query ast.Body) *eval {
	cpy := *e
	cpy.index = 0
	cpy.query = query
	cpy.queryID = cpy.queryIDFact.Next()
	cpy.parent = e
	cpy.findOne = false
	return &cpy
}

func (e *eval) child(query ast.Body) *eval {
	cpy := *e
	cpy.index = 0
	cpy.query = query
	cpy.queryID = cpy.queryIDFact.Next()
	cpy.bindings = newBindings(cpy.queryID, e.instr)
	cpy.parent = e
	cpy.findOne = false
	return &cpy
}

func (e *eval) next(iter evalIterator) error {
	e.index++
	err := e.evalExpr(iter)
	e.index--
	return err
}

func (e *eval) partial() bool {
	return e.saveSet != nil
}

func (e *eval) unknown(x interface{}, b *bindings) bool {
	if !e.partial() {
		return false
	}

	// If the caller provided an ast.Value directly (e.g., an ast.Ref) wrap
	// it as an ast.Term because the saveSet Contains() function expects
	// ast.Term.
	if v, ok := x.(ast.Value); ok {
		x = ast.NewTerm(v)
	}

	return saveRequired(e.compiler, e.inliningControl, true, e.saveSet, b, x, false)
}

func (e *eval) traceEnter(x ast.Node) {
	e.traceEvent(EnterOp, x, "", nil)
}

func (e *eval) traceExit(x ast.Node) {
	var msg string
	if e.findOne {
		msg = "early"
	}
	e.traceEvent(ExitOp, x, msg, nil)
}

func (e *eval) traceEval(x ast.Node) {
	e.traceEvent(EvalOp, x, "", nil)
}

func (e *eval) traceDuplicate(x ast.Node) {
	e.traceEvent(DuplicateOp, x, "", nil)
}

func (e *eval) traceFail(x ast.Node) {
	e.traceEvent(FailOp, x, "", nil)
}

func (e *eval) traceRedo(x ast.Node) {
	e.traceEvent(RedoOp, x, "", nil)
}

func (e *eval) traceSave(x ast.Node) {
	e.traceEvent(SaveOp, x, "", nil)
}

func (e *eval) traceIndex(x ast.Node, msg string, target *ast.Ref) {
	e.traceEvent(IndexOp, x, msg, target)
}

func (e *eval) traceWasm(x ast.Node, target *ast.Ref) {
	e.traceEvent(WasmOp, x, "", target)
}

func (e *eval) traceEvent(op Op, x ast.Node, msg string, target *ast.Ref) {

	if !e.traceEnabled {
		return
	}

	var parentID uint64
	if e.parent != nil {
		parentID = e.parent.queryID
	}

	evt := Event{
		QueryID:  e.queryID,
		ParentID: parentID,
		Op:       op,
		Node:     x,
		Location: x.Loc(),
		Message:  msg,
		Ref:      target,
		input:    e.input,
		bindings: e.bindings,
	}

	// Skip plugging the local variables, unless any of the tracers
	// had required it via their configuration. If any required the
	// variable bindings then we will plug and give values for all
	// tracers.
	if e.plugTraceVars {

		evt.Locals = ast.NewValueMap()
		evt.LocalMetadata = map[ast.Var]VarMetadata{}

		_ = e.bindings.Iter(nil, func(k, v *ast.Term) error {
			original := k.Value.(ast.Var)
			rewritten, _ := e.rewrittenVar(original)
			evt.LocalMetadata[original] = VarMetadata{
				Name:     rewritten,
				Location: k.Loc(),
			}

			// For backwards compatibility save a copy of the values too..
			evt.Locals.Put(k.Value, v.Value)
			return nil
		}) // cannot return error

		ast.WalkTerms(x, func(term *ast.Term) bool {
			if v, ok := term.Value.(ast.Var); ok {
				if _, ok := evt.LocalMetadata[v]; !ok {
					if rewritten, ok := e.rewrittenVar(v); ok {
						evt.LocalMetadata[v] = VarMetadata{
							Name:     rewritten,
							Location: term.Loc(),
						}
					}
				}
			}
			return false
		})
	}

	for i := range e.tracers {
		e.tracers[i].TraceEvent(evt)
	}
}

func (e *eval) eval(iter evalIterator) error {
	return e.evalExpr(iter)
}

func (e *eval) evalExpr(iter evalIterator) error {

	if e.cancel != nil && e.cancel.Cancelled() {
		return &Error{
			Code:    CancelErr,
			Message: "caller cancelled query execution",
		}
	}

	if e.index >= len(e.query) {
		err := iter(e)
		if err != nil {
			ee, ok := err.(*earlyExitError)
			if !ok {
				return err
			}
			if !e.findOne {
				return nil
			}
			return &earlyExitError{prev: ee, e: e}
		}
		if e.findOne && !e.partial() { // we've found one!
			return &earlyExitError{e: e}
		}
		return nil
	}

	expr := e.query[e.index]

	e.traceEval(expr)

	if len(expr.With) > 0 {
		return e.evalWith(iter)
	}

	return e.evalStep(func(e *eval) error {
		return e.next(iter)
	})
}

func (e *eval) evalStep(iter evalIterator) error {

	expr := e.query[e.index]

	if expr.Negated {
		return e.evalNot(iter)
	}

	var defined bool
	var err error

	switch terms := expr.Terms.(type) {
	case []*ast.Term:
		if expr.IsEquality() {
			err = e.unify(terms[1], terms[2], func() error {
				defined = true
				err := iter(e)
				e.traceRedo(expr)
				return err
			})
		} else {
			err = e.evalCall(terms, func() error {
				defined = true
				err := iter(e)
				e.traceRedo(expr)
				return err
			})
		}
	case *ast.Term:
		rterm := e.generateVar(fmt.Sprintf("term_%d_%d", e.queryID, e.index))
		err = e.unify(terms, rterm, func() error {
			if e.saveSet.Contains(rterm, e.bindings) {
				return e.saveExpr(ast.NewExpr(rterm), e.bindings, func() error {
					return iter(e)
				})
			}
			if !e.bindings.Plug(rterm).Equal(ast.BooleanTerm(false)) {
				defined = true
				err := iter(e)
				e.traceRedo(expr)
				return err
			}
			return nil
		})
	}

	if err != nil {
		return err
	}

	if !defined {
		e.traceFail(expr)
	}

	return nil
}

func (e *eval) evalNot(iter evalIterator) error {

	expr := e.query[e.index]

	if e.unknown(expr, e.bindings) {
		return e.evalNotPartial(iter)
	}

	negation := ast.NewBody(expr.Complement().NoWith())
	child := e.closure(negation)

	var defined bool
	child.traceEnter(negation)

	err := child.eval(func(*eval) error {
		child.traceExit(negation)
		defined = true
		child.traceRedo(negation)
		return nil
	})

	if err != nil {
		return err
	}

	if !defined {
		return iter(e)
	}

	e.traceFail(expr)
	return nil
}

func (e *eval) evalWith(iter evalIterator) error {

	expr := e.query[e.index]
	var disable []ast.Ref

	if e.partial() {

		// If the value is unknown the with statement cannot be evaluated and so
		// the entire expression should be saved to be safe. In the future this
		// could be relaxed in certain cases (e.g., if the with statement would
		// have no affect.)
		for _, with := range expr.With {
			if e.saveSet.ContainsRecursive(with.Value, e.bindings) {
				return e.saveExprMarkUnknowns(expr, e.bindings, func() error {
					return e.next(iter)
				})
			}
		}

		// Disable inlining on all references in the expression so the result of
		// partial evaluation has the same semantics w/ the with statements
		// preserved.
		ast.WalkRefs(expr, func(x ast.Ref) bool {
			disable = append(disable, x.GroundPrefix())
			return false
		})
	}

	pairsInput := [][2]*ast.Term{}
	pairsData := [][2]*ast.Term{}
	targets := []ast.Ref{}

	for i := range expr.With {
		plugged := e.bindings.Plug(expr.With[i].Value)
		if isInputRef(expr.With[i].Target) {
			pairsInput = append(pairsInput, [...]*ast.Term{expr.With[i].Target, plugged})
		} else if isDataRef(expr.With[i].Target) {
			pairsData = append(pairsData, [...]*ast.Term{expr.With[i].Target, plugged})
		}
		targets = append(targets, expr.With[i].Target.Value.(ast.Ref))
	}

	input, err := mergeTermWithValues(e.input, pairsInput)
	if err != nil {
		return &Error{
			Code:     ConflictErr,
			Location: expr.Location,
			Message:  err.Error(),
		}
	}

	data, err := mergeTermWithValues(e.data, pairsData)
	if err != nil {
		return &Error{
			Code:     ConflictErr,
			Location: expr.Location,
			Message:  err.Error(),
		}
	}

	oldInput, oldData := e.evalWithPush(input, data, targets, disable)

	err = e.evalStep(func(e *eval) error {
		e.evalWithPop(oldInput, oldData)
		err := e.next(iter)
		oldInput, oldData = e.evalWithPush(input, data, targets, disable)
		return err
	})

	e.evalWithPop(oldInput, oldData)

	return err
}

func (e *eval) evalWithPush(input, data *ast.Term, targets, disable []ast.Ref) (*ast.Term, *ast.Term) {
	var oldInput *ast.Term

	if input != nil {
		oldInput = e.input
		e.input = input
	}

	var oldData *ast.Term

	if data != nil {
		oldData = e.data
		e.data = data
	}

	e.comprehensionCache.Push()
	e.virtualCache.Push()
	e.targetStack.Push(targets)
	e.inliningControl.PushDisable(disable, true)

	return oldInput, oldData
}

func (e *eval) evalWithPop(input, data *ast.Term) {
	e.inliningControl.PopDisable()
	e.targetStack.Pop()
	e.virtualCache.Pop()
	e.comprehensionCache.Pop()
	e.data = data
	e.input = input
}

func (e *eval) evalNotPartial(iter evalIterator) error {

	// Prepare query normally.
	expr := e.query[e.index]
	negation := expr.Complement().NoWith()
	child := e.closure(ast.NewBody(negation))

	// Unknowns is the set of variables that are marked as unknown. The variables
	// are namespaced with the query ID that they originate in. This ensures that
	// variables across two or more queries are identified uniquely.
	//
	// NOTE(tsandall): this is greedy in the sense that we only need variable
	// dependencies of the negation.
	unknowns := e.saveSet.Vars(e.caller.bindings)

	// Run partial evaluation. Since the result may require support, push a new
	// query onto the save stack to avoid mutating the current save query. If
	// shallow inlining is not enabled, run copy propagation to further simplify
	// the result.
	var cp *copypropagation.CopyPropagator

	if !e.inliningControl.shallow {
		cp = copypropagation.New(unknowns).WithEnsureNonEmptyBody(true).WithCompiler(e.compiler)
	}

	var savedQueries []ast.Body
	e.saveStack.PushQuery(nil)

	_ = child.eval(func(*eval) error {
		query := e.saveStack.Peek()
		plugged := query.Plug(e.caller.bindings)
		// Skip this rule body if it fails to type-check.
		// Type-checking failure means the rule body will never succeed.
		if !e.compiler.PassesTypeCheck(plugged) {
			return nil
		}
		if cp != nil {
			plugged = applyCopyPropagation(cp, e.instr, plugged)
		}
		savedQueries = append(savedQueries, plugged)
		return nil
	}) // cannot return error

	e.saveStack.PopQuery()

	// If partial evaluation produced no results, the expression is always undefined
	// so it does not have to be saved.
	if len(savedQueries) == 0 {
		return iter(e)
	}

	// Check if the partial evaluation result can be inlined in this query. If not,
	// generate support rules for the result. Depending on the size of the partial
	// evaluation result and the contents, it may or may not be inlinable. We treat
	// the unknowns as safe because vars in the save set will either be known to
	// the caller or made safe by an expression on the save stack.
	if !canInlineNegation(unknowns, savedQueries) {
		return e.evalNotPartialSupport(child.queryID, expr, unknowns, savedQueries, iter)
	}

	// If we can inline the result, we have to generate the cross product of the
	// queries. For example:
	//
	//	(A && B) || (C && D)
	//
	// Becomes:
	//
	//	(!A && !C) || (!A && !D) || (!B && !C) || (!B && !D)
	return complementedCartesianProduct(savedQueries, 0, nil, func(q ast.Body) error {
		return e.saveInlinedNegatedExprs(q, func() error {
			return iter(e)
		})
	})
}

func (e *eval) evalNotPartialSupport(negationID uint64, expr *ast.Expr, unknowns ast.VarSet, queries []ast.Body, iter evalIterator) error {

	// Prepare support rule head.
	supportName := fmt.Sprintf("__not%d_%d_%d__", e.queryID, e.index, negationID)
	term := ast.RefTerm(ast.DefaultRootDocument, e.saveNamespace, ast.StringTerm(supportName))
	path := term.Value.(ast.Ref)
	head := ast.NewHead(ast.Var(supportName), nil, ast.BooleanTerm(true))

	bodyVars := ast.NewVarSet()

	for _, q := range queries {
		bodyVars.Update(q.Vars(ast.VarVisitorParams{}))
	}

	unknowns = unknowns.Intersect(bodyVars)

	// Make rule args. Sort them to ensure order is deterministic.
	args := make([]*ast.Term, 0, len(unknowns))

	for v := range unknowns {
		args = append(args, ast.NewTerm(v))
	}

	sort.Slice(args, func(i, j int) bool {
		return args[i].Value.Compare(args[j].Value) < 0
	})

	if len(args) > 0 {
		head.Args = args
	}

	// Save support rules.
	for _, query := range queries {
		e.saveSupport.Insert(path, &ast.Rule{
			Head: head,
			Body: query,
		})
	}

	// Save expression that refers to support rule set.

	terms := expr.Terms
	expr.Terms = nil // Prevent unnecessary copying the terms.
	cpy := expr.Copy()
	expr.Terms = terms

	if len(args) > 0 {
		terms := make([]*ast.Term, len(args)+1)
		terms[0] = term
		for i := 0; i < len(args); i++ {
			terms[i+1] = args[i]
		}
		cpy.Terms = terms
	} else {
		cpy.Terms = term
	}

	return e.saveInlinedNegatedExprs([]*ast.Expr{cpy}, func() error {
		return e.next(iter)
	})
}

func (e *eval) evalCall(terms []*ast.Term, iter unifyIterator) error {

	ref := terms[0].Value.(ast.Ref)

	if ref[0].Equal(ast.DefaultRootDocument) {
		var ir *ast.IndexResult
		var err error
		if e.partial() {
			ir, err = e.getRules(ref, nil)
		} else {
			ir, err = e.getRules(ref, terms[1:])
		}
		if err != nil {
			return err
		}
		eval := evalFunc{
			e:     e,
			ref:   ref,
			terms: terms,
			ir:    ir,
		}
		return eval.eval(iter)
	}

	bi, f, ok := e.builtinFunc(ref.String())
	if !ok {
		return unsupportedBuiltinErr(e.query[e.index].Location)
	}

	if e.unknown(e.query[e.index], e.bindings) {
		return e.saveCall(len(bi.Decl.Args()), terms, iter)
	}

	var parentID uint64
	if e.parent != nil {
		parentID = e.parent.queryID
	}

	var capabilities *ast.Capabilities
	if e.compiler != nil {
		capabilities = e.compiler.Capabilities()
	}

	bctx := BuiltinContext{
		Context:                e.ctx,
		Metrics:                e.metrics,
		Seed:                   e.seed,
		Time:                   e.time,
		Cancel:                 e.cancel,
		Runtime:                e.runtime,
		Cache:                  e.builtinCache,
		InterQueryBuiltinCache: e.interQueryBuiltinCache,
		Location:               e.query[e.index].Location,
		QueryTracers:           e.tracers,
		TraceEnabled:           e.traceEnabled,
		QueryID:                e.queryID,
		ParentID:               parentID,
		PrintHook:              e.printHook,
		DistributedTracingOpts: e.tracingOpts,
		Capabilities:           capabilities,
	}

	eval := evalBuiltin{
		e:     e,
		bi:    bi,
		bctx:  bctx,
		f:     f,
		terms: terms[1:],
	}
	return eval.eval(iter)
}

func (e *eval) unify(a, b *ast.Term, iter unifyIterator) error {
	return e.biunify(a, b, e.bindings, e.bindings, iter)
}

func (e *eval) biunify(a, b *ast.Term, b1, b2 *bindings, iter unifyIterator) error {
	a, b1 = b1.apply(a)
	b, b2 = b2.apply(b)
	switch vA := a.Value.(type) {
	case ast.Var, ast.Ref, *ast.ArrayComprehension, *ast.SetComprehension, *ast.ObjectComprehension:
		return e.biunifyValues(a, b, b1, b2, iter)
	case ast.Null:
		switch b.Value.(type) {
		case ast.Var, ast.Null, ast.Ref:
			return e.biunifyValues(a, b, b1, b2, iter)
		}
	case ast.Boolean:
		switch b.Value.(type) {
		case ast.Var, ast.Boolean, ast.Ref:
			return e.biunifyValues(a, b, b1, b2, iter)
		}
	case ast.Number:
		switch b.Value.(type) {
		case ast.Var, ast.Number, ast.Ref:
			return e.biunifyValues(a, b, b1, b2, iter)
		}
	case ast.String:
		switch b.Value.(type) {
		case ast.Var, ast.String, ast.Ref:
			return e.biunifyValues(a, b, b1, b2, iter)
		}
	case *ast.Array:
		switch vB := b.Value.(type) {
		case ast.Var, ast.Ref, *ast.ArrayComprehension:
			return e.biunifyValues(a, b, b1, b2, iter)
		case *ast.Array:
			return e.biunifyArrays(vA, vB, b1, b2, iter)
		}
	case ast.Object:
		switch vB := b.Value.(type) {
		case ast.Var, ast.Ref, *ast.ObjectComprehension:
			return e.biunifyValues(a, b, b1, b2, iter)
		case ast.Object:
			return e.biunifyObjects(vA, vB, b1, b2, iter)
		}
	case ast.Set:
		return e.biunifyValues(a, b, b1, b2, iter)
	}
	return nil
}

func (e *eval) biunifyArrays(a, b *ast.Array, b1, b2 *bindings, iter unifyIterator) error {
	if a.Len() != b.Len() {
		return nil
	}
	return e.biunifyArraysRec(a, b, b1, b2, iter, 0)
}

func (e *eval) biunifyArraysRec(a, b *ast.Array, b1, b2 *bindings, iter unifyIterator, idx int) error {
	if idx == a.Len() {
		return iter()
	}
	return e.biunify(a.Elem(idx), b.Elem(idx), b1, b2, func() error {
		return e.biunifyArraysRec(a, b, b1, b2, iter, idx+1)
	})
}

func (e *eval) biunifyObjects(a, b ast.Object, b1, b2 *bindings, iter unifyIterator) error {
	if a.Len() != b.Len() {
		return nil
	}

	// Objects must not contain unbound variables as keys at this point as we
	// cannot unify them. Similar to sets, plug both sides before comparing the
	// keys and unifying the values.
	if nonGroundKeys(a) {
		a = plugKeys(a, b1)
	}

	if nonGroundKeys(b) {
		b = plugKeys(b, b2)
	}

	return e.biunifyObjectsRec(a, b, b1, b2, iter, a, 0)
}

func (e *eval) biunifyObjectsRec(a, b ast.Object, b1, b2 *bindings, iter unifyIterator, keys ast.Object, idx int) error {
	if idx == keys.Len() {
		return iter()
	}
	key, _ := keys.Elem(idx)
	v2 := b.Get(key)
	if v2 == nil {
		return nil
	}
	return e.biunify(a.Get(key), v2, b1, b2, func() error {
		return e.biunifyObjectsRec(a, b, b1, b2, iter, keys, idx+1)
	})
}

func (e *eval) biunifyValues(a, b *ast.Term, b1, b2 *bindings, iter unifyIterator) error {
	// Try to evaluate refs and comprehensions. If partial evaluation is
	// enabled, then skip evaluation (and save the expression) if the term is
	// in the save set. Currently, comprehensions are not evaluated during
	// partial eval. This could be improved in the future.

	var saveA, saveB bool

	if _, ok := a.Value.(ast.Set); ok {
		saveA = e.saveSet.ContainsRecursive(a, b1)
	} else {
		saveA = e.saveSet.Contains(a, b1)
		if !saveA {
			if _, refA := a.Value.(ast.Ref); refA {
				return e.biunifyRef(a, b, b1, b2, iter)
			}
		}
	}

	if _, ok := b.Value.(ast.Set); ok {
		saveB = e.saveSet.ContainsRecursive(b, b2)
	} else {
		saveB = e.saveSet.Contains(b, b2)
		if !saveB {
			if _, refB := b.Value.(ast.Ref); refB {
				return e.biunifyRef(b, a, b2, b1, iter)
			}
		}
	}

	if saveA || saveB {
		return e.saveUnify(a, b, b1, b2, iter)
	}

	if ast.IsComprehension(a.Value) {
		return e.biunifyComprehension(a, b, b1, b2, false, iter)
	} else if ast.IsComprehension(b.Value) {
		return e.biunifyComprehension(b, a, b2, b1, true, iter)
	}

	// Perform standard unification.
	_, varA := a.Value.(ast.Var)
	_, varB := b.Value.(ast.Var)

	var undo undo

	if varA && varB {
		if b1 == b2 && a.Equal(b) {
			return iter()
		}
		b1.bind(a, b, b2, &undo)
		err := iter()
		undo.Undo()
		return err
	} else if varA && !varB {
		b1.bind(a, b, b2, &undo)
		err := iter()
		undo.Undo()
		return err
	} else if varB && !varA {
		b2.bind(b, a, b1, &undo)
		err := iter()
		undo.Undo()
		return err
	}

	// Sets must not contain unbound variables at this point as we cannot unify
	// them. So simply plug both sides (to substitute any bound variables with
	// values) and then check for equality.
	switch a.Value.(type) {
	case ast.Set:
		a = b1.Plug(a)
		b = b2.Plug(b)
	}

	if a.Equal(b) {
		return iter()
	}

	return nil
}

func (e *eval) biunifyRef(a, b *ast.Term, b1, b2 *bindings, iter unifyIterator) error {

	ref := a.Value.(ast.Ref)

	if ref[0].Equal(ast.DefaultRootDocument) {
		node := e.compiler.RuleTree.Child(ref[0].Value)
		eval := evalTree{
			e:         e,
			ref:       ref,
			pos:       1,
			plugged:   ref.Copy(),
			bindings:  b1,
			rterm:     b,
			rbindings: b2,
			node:      node,
		}
		return eval.eval(iter)
	}

	var term *ast.Term
	var termbindings *bindings

	if ref[0].Equal(ast.InputRootDocument) {
		term = e.input
		termbindings = b1
	} else {
		term, termbindings = b1.apply(ref[0])
		if term == ref[0] {
			term = nil
		}
	}

	if term == nil {
		return nil
	}

	eval := evalTerm{
		e:            e,
		ref:          ref,
		pos:          1,
		bindings:     b1,
		term:         term,
		termbindings: termbindings,
		rterm:        b,
		rbindings:    b2,
	}

	return eval.eval(iter)
}

func (e *eval) biunifyComprehension(a, b *ast.Term, b1, b2 *bindings, swap bool, iter unifyIterator) error {

	if e.unknown(a, b1) {
		return e.biunifyComprehensionPartial(a, b, b1, b2, swap, iter)
	}

	value, err := e.buildComprehensionCache(a)

	if err != nil {
		return err
	} else if value != nil {
		return e.biunify(value, b, b1, b2, iter)
	} else {
		e.instr.counterIncr(evalOpComprehensionCacheMiss)
	}

	switch a := a.Value.(type) {
	case *ast.ArrayComprehension:
		return e.biunifyComprehensionArray(a, b, b1, b2, iter)
	case *ast.SetComprehension:
		return e.biunifyComprehensionSet(a, b, b1, b2, iter)
	case *ast.ObjectComprehension:
		return e.biunifyComprehensionObject(a, b, b1, b2, iter)
	}

	return internalErr(e.query[e.index].Location, "illegal comprehension type")
}

func (e *eval) buildComprehensionCache(a *ast.Term) (*ast.Term, error) {

	index := e.comprehensionIndex(a)
	if index == nil {
		e.instr.counterIncr(evalOpComprehensionCacheSkip)
		return nil, nil
	}

	cache, ok := e.comprehensionCache.Elem(a)
	if !ok {
		var err error
		switch x := a.Value.(type) {
		case *ast.ArrayComprehension:
			cache, err = e.buildComprehensionCacheArray(x, index.Keys)
		case *ast.SetComprehension:
			cache, err = e.buildComprehensionCacheSet(x, index.Keys)
		case *ast.ObjectComprehension:
			cache, err = e.buildComprehensionCacheObject(x, index.Keys)
		default:
			err = internalErr(e.query[e.index].Location, "illegal comprehension type")
		}
		if err != nil {
			return nil, err
		}
		e.comprehensionCache.Set(a, cache)
		e.instr.counterIncr(evalOpComprehensionCacheBuild)
	} else {
		e.instr.counterIncr(evalOpComprehensionCacheHit)
	}

	values := make([]*ast.Term, len(index.Keys))

	for i := range index.Keys {
		values[i] = e.bindings.Plug(index.Keys[i])
	}

	return cache.Get(values), nil
}

func (e *eval) buildComprehensionCacheArray(x *ast.ArrayComprehension, keys []*ast.Term) (*comprehensionCacheElem, error) {
	child := e.child(x.Body)
	node := newComprehensionCacheElem()
	return node, child.Run(func(child *eval) error {
		values := make([]*ast.Term, len(keys))
		for i := range keys {
			values[i] = child.bindings.Plug(keys[i])
		}
		head := child.bindings.Plug(x.Term)
		cached := node.Get(values)
		if cached != nil {
			cached.Value = cached.Value.(*ast.Array).Append(head)
		} else {
			node.Put(values, ast.ArrayTerm(head))
		}
		return nil
	})
}

func (e *eval) buildComprehensionCacheSet(x *ast.SetComprehension, keys []*ast.Term) (*comprehensionCacheElem, error) {
	child := e.child(x.Body)
	node := newComprehensionCacheElem()
	return node, child.Run(func(child *eval) error {
		values := make([]*ast.Term, len(keys))
		for i := range keys {
			values[i] = child.bindings.Plug(keys[i])
		}
		head := child.bindings.Plug(x.Term)
		cached := node.Get(values)
		if cached != nil {
			set := cached.Value.(ast.Set)
			set.Add(head)
		} else {
			node.Put(values, ast.SetTerm(head))
		}
		return nil
	})
}

func (e *eval) buildComprehensionCacheObject(x *ast.ObjectComprehension, keys []*ast.Term) (*comprehensionCacheElem, error) {
	child := e.child(x.Body)
	node := newComprehensionCacheElem()
	return node, child.Run(func(child *eval) error {
		values := make([]*ast.Term, len(keys))
		for i := range keys {
			values[i] = child.bindings.Plug(keys[i])
		}
		headKey := child.bindings.Plug(x.Key)
		headValue := child.bindings.Plug(x.Value)
		cached := node.Get(values)
		if cached != nil {
			obj := cached.Value.(ast.Object)
			obj.Insert(headKey, headValue)
		} else {
			node.Put(values, ast.ObjectTerm(ast.Item(headKey, headValue)))
		}
		return nil
	})
}

func (e *eval) biunifyComprehensionPartial(a, b *ast.Term, b1, b2 *bindings, swap bool, iter unifyIterator) error {
	var err error
	cpyA, err := e.amendComprehension(a, b1)
	if err != nil {
		return err
	}

	if ast.IsComprehension(b.Value) {
		b, err = e.amendComprehension(b, b2)
		if err != nil {
			return err
		}
	}

	// The other term might need to be plugged so include the bindings. The
	// bindings for the comprehension term are saved (for compatibility) but
	// the eventual plug operation on the comprehension will be a no-op.
	if !swap {
		return e.saveUnify(cpyA, b, b1, b2, iter)
	}

	return e.saveUnify(b, cpyA, b2, b1, iter)
}

// amendComprehension captures bindings available to the comprehension,
// and used within its term or body.
func (e *eval) amendComprehension(a *ast.Term, b1 *bindings) (*ast.Term, error) {
	cpyA := a.Copy()

	// Namespace the variables in the body to avoid collision when the final
	// queries returned by partial evaluation.
	var body *ast.Body

	switch a := cpyA.Value.(type) {
	case *ast.ArrayComprehension:
		body = &a.Body
	case *ast.SetComprehension:
		body = &a.Body
	case *ast.ObjectComprehension:
		body = &a.Body
	default:
		return nil, fmt.Errorf("illegal comprehension %T", a)
	}

	vars := a.Vars()
	err := b1.Iter(e.caller.bindings, func(k, v *ast.Term) error {
		if vars.Contains(k.Value.(ast.Var)) {
			body.Append(ast.Equality.Expr(k, v))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	b1.Namespace(cpyA, e.caller.bindings)
	return cpyA, nil
}

func (e *eval) biunifyComprehensionArray(x *ast.ArrayComprehension, b *ast.Term, b1, b2 *bindings, iter unifyIterator) error {
	result := ast.NewArray()
	child := e.closure(x.Body)
	err := child.Run(func(child *eval) error {
		result = result.Append(child.bindings.Plug(x.Term))
		return nil
	})
	if err != nil {
		return err
	}
	return e.biunify(ast.NewTerm(result), b, b1, b2, iter)
}

func (e *eval) biunifyComprehensionSet(x *ast.SetComprehension, b *ast.Term, b1, b2 *bindings, iter unifyIterator) error {
	result := ast.NewSet()
	child := e.closure(x.Body)
	err := child.Run(func(child *eval) error {
		result.Add(child.bindings.Plug(x.Term))
		return nil
	})
	if err != nil {
		return err
	}
	return e.biunify(ast.NewTerm(result), b, b1, b2, iter)
}

func (e *eval) biunifyComprehensionObject(x *ast.ObjectComprehension, b *ast.Term, b1, b2 *bindings, iter unifyIterator) error {
	result := ast.NewObject()
	child := e.closure(x.Body)
	err := child.Run(func(child *eval) error {
		key := child.bindings.Plug(x.Key)
		value := child.bindings.Plug(x.Value)
		exist := result.Get(key)
		if exist != nil && !exist.Equal(value) {
			return objectDocKeyConflictErr(x.Key.Location)
		}
		result.Insert(key, value)
		return nil
	})
	if err != nil {
		return err
	}
	return e.biunify(ast.NewTerm(result), b, b1, b2, iter)
}

func (e *eval) saveExpr(expr *ast.Expr, b *bindings, iter unifyIterator) error {
	expr.With = e.query[e.index].With
	expr.Location = e.query[e.index].Location
	e.saveStack.Push(expr, b, b)
	e.traceSave(expr)
	err := iter()
	e.saveStack.Pop()
	return err
}

func (e *eval) saveExprMarkUnknowns(expr *ast.Expr, b *bindings, iter unifyIterator) error {
	expr.With = e.query[e.index].With
	expr.Location = e.query[e.index].Location
	declArgsLen, err := e.getDeclArgsLen(expr)
	if err != nil {
		return err
	}
	var pops int
	if pairs := getSavePairsFromExpr(declArgsLen, expr, b, nil); len(pairs) > 0 {
		pops += len(pairs)
		for _, p := range pairs {
			e.saveSet.Push([]*ast.Term{p.term}, p.b)
		}
	}
	e.saveStack.Push(expr, b, b)
	e.traceSave(expr)
	err = iter()
	e.saveStack.Pop()
	for i := 0; i < pops; i++ {
		e.saveSet.Pop()
	}
	return err
}

func (e *eval) saveUnify(a, b *ast.Term, b1, b2 *bindings, iter unifyIterator) error {
	e.instr.startTimer(partialOpSaveUnify)
	expr := ast.Equality.Expr(a, b)
	expr.With = e.query[e.index].With
	expr.Location = e.query[e.index].Location
	pops := 0
	if pairs := getSavePairsFromTerm(a, b1, nil); len(pairs) > 0 {
		pops += len(pairs)
		for _, p := range pairs {
			e.saveSet.Push([]*ast.Term{p.term}, p.b)
		}

	}
	if pairs := getSavePairsFromTerm(b, b2, nil); len(pairs) > 0 {
		pops += len(pairs)
		for _, p := range pairs {
			e.saveSet.Push([]*ast.Term{p.term}, p.b)
		}
	}
	e.saveStack.Push(expr, b1, b2)
	e.traceSave(expr)
	e.instr.stopTimer(partialOpSaveUnify)
	err := iter()

	e.saveStack.Pop()
	for i := 0; i < pops; i++ {
		e.saveSet.Pop()
	}

	return err
}

func (e *eval) saveCall(declArgsLen int, terms []*ast.Term, iter unifyIterator) error {
	expr := ast.NewExpr(terms)
	expr.With = e.query[e.index].With
	expr.Location = e.query[e.index].Location

	// If call-site includes output value then partial eval must add vars in output
	// position to the save set.
	pops := 0
	if declArgsLen == len(terms)-2 {
		if pairs := getSavePairsFromTerm(terms[len(terms)-1], e.bindings, nil); len(pairs) > 0 {
			pops += len(pairs)
			for _, p := range pairs {
				e.saveSet.Push([]*ast.Term{p.term}, p.b)
			}
		}
	}
	e.saveStack.Push(expr, e.bindings, nil)
	e.traceSave(expr)
	err := iter()

	e.saveStack.Pop()
	for i := 0; i < pops; i++ {
		e.saveSet.Pop()
	}
	return err
}

func (e *eval) saveInlinedNegatedExprs(exprs []*ast.Expr, iter unifyIterator) error {

	with := make([]*ast.With, len(e.query[e.index].With))

	for i := range e.query[e.index].With {
		cpy := e.query[e.index].With[i].Copy()
		cpy.Value = e.bindings.PlugNamespaced(cpy.Value, e.caller.bindings)
		with[i] = cpy
	}

	for _, expr := range exprs {
		expr.With = with
		e.saveStack.Push(expr, nil, nil)
		e.traceSave(expr)
	}
	err := iter()
	for i := 0; i < len(exprs); i++ {
		e.saveStack.Pop()
	}
	return err
}

func (e *eval) getRules(ref ast.Ref, args []*ast.Term) (*ast.IndexResult, error) {
	e.instr.startTimer(evalOpRuleIndex)
	defer e.instr.stopTimer(evalOpRuleIndex)

	index := e.compiler.RuleIndex(ref)
	if index == nil {
		return nil, nil
	}

	var result *ast.IndexResult
	var err error
	if e.indexing {
		result, err = index.Lookup(&evalResolver{e: e, args: args})
	} else {
		result, err = index.AllRules(&evalResolver{e: e})
	}
	if err != nil {
		return nil, err
	}

	result.EarlyExit = result.EarlyExit && e.earlyExit

	var msg strings.Builder
	if len(result.Rules) == 1 {
		msg.WriteString("(matched 1 rule")
	} else {
		msg.Grow(len("(matched NNNN rules)"))
		msg.WriteString("(matched ")
		msg.WriteString(strconv.Itoa(len(result.Rules)))
		msg.WriteString(" rules")
	}
	if result.EarlyExit {
		msg.WriteString(", early exit")
	}
	msg.WriteRune(')')
	e.traceIndex(e.query[e.index], msg.String(), &ref)
	return result, err
}

func (e *eval) Resolve(ref ast.Ref) (ast.Value, error) {
	return (&evalResolver{e: e}).Resolve(ref)
}

type evalResolver struct {
	e    *eval
	args []*ast.Term
}

func (e *evalResolver) Resolve(ref ast.Ref) (ast.Value, error) {
	e.e.instr.startTimer(evalOpResolve)

	if e.e.inliningControl.Disabled(ref, true) || e.e.saveSet.Contains(ast.NewTerm(ref), nil) {
		e.e.instr.stopTimer(evalOpResolve)
		return nil, ast.UnknownValueErr{}
	}

	// Lookup of function argument values works by using the `args` ref[0],
	// where the ast.Number in ref[1] references the function argument of
	// that number. The callsite-local arguments are passed in e.args,
	// indexed by argument index.
	if ref[0].Equal(ast.FunctionArgRootDocument) {
		v, ok := ref[1].Value.(ast.Number)
		if ok {
			i, ok := v.Int()
			if ok && i >= 0 && i < len(e.args) {
				e.e.instr.stopTimer(evalOpResolve)
				plugged := e.e.bindings.PlugNamespaced(e.args[i], e.e.caller.bindings)
				return plugged.Value, nil
			}
		}
		e.e.instr.stopTimer(evalOpResolve)
		return nil, ast.UnknownValueErr{}
	}

	if ref[0].Equal(ast.InputRootDocument) {
		if e.e.input != nil {
			v, err := e.e.input.Value.Find(ref[1:])
			if err != nil {
				v = nil
			}
			e.e.instr.stopTimer(evalOpResolve)
			return v, nil
		}
		e.e.instr.stopTimer(evalOpResolve)
		return nil, nil
	}

	if ref[0].Equal(ast.DefaultRootDocument) {

		var repValue ast.Value

		if e.e.data != nil {
			if v, err := e.e.data.Value.Find(ref[1:]); err == nil {
				repValue = v
			} else {
				repValue = nil
			}
		}

		if e.e.targetStack.Prefixed(ref) {
			e.e.instr.stopTimer(evalOpResolve)
			return repValue, nil
		}

		var merged ast.Value
		var err error

		// Converting large JSON values into AST values can be fairly expensive. For
		// example, a 2MB JSON value can take upwards of 30 millisceonds to convert.
		// We cache the result of conversion here in case the same base document is
		// being read multiple times during evaluation.
		realValue := e.e.baseCache.Get(ref)
		if realValue != nil {
			e.e.instr.counterIncr(evalOpBaseCacheHit)
			if repValue == nil {
				e.e.instr.stopTimer(evalOpResolve)
				return realValue, nil
			}
			var ok bool
			merged, ok = merge(repValue, realValue)
			if !ok {
				err = mergeConflictErr(ref[0].Location)
			}
		} else {
			e.e.instr.counterIncr(evalOpBaseCacheMiss)
			merged, err = e.e.resolveReadFromStorage(ref, repValue)
		}
		e.e.instr.stopTimer(evalOpResolve)
		return merged, err
	}
	e.e.instr.stopTimer(evalOpResolve)
	return nil, fmt.Errorf("illegal ref")
}

func (e *eval) resolveReadFromStorage(ref ast.Ref, a ast.Value) (ast.Value, error) {
	if refContainsNonScalar(ref) {
		return a, nil
	}

	v, err := e.external.Resolve(e, ref)

	if err != nil {
		return nil, err
	} else if v == nil {

		path, err := storage.NewPathForRef(ref)
		if err != nil {
			if !storage.IsNotFound(err) {
				return nil, err
			}
			return a, nil
		}

		blob, err := e.store.Read(e.ctx, e.txn, path)
		if err != nil {
			if !storage.IsNotFound(err) {
				return nil, err
			}
			return a, nil
		}

		if len(path) == 0 {
			switch obj := blob.(type) {
			case map[string]interface{}:
				if len(obj) > 0 {
					cpy := make(map[string]interface{}, len(obj)-1)
					for k, v := range obj {
						if string(ast.SystemDocumentKey) != k {
							cpy[k] = v
						}
					}
					blob = cpy
				}
			case ast.Object:
				if obj.Len() > 0 {
					cpy := ast.NewObject()
					if err := obj.Iter(func(k *ast.Term, v *ast.Term) error {
						if !ast.SystemDocumentKey.Equal(k.Value) {
							cpy.Insert(k, v)
						}
						return nil
					}); err != nil {
						return nil, err
					}
					blob = cpy

				}
			}
		}

		var ok bool
		v, ok = blob.(ast.Value)
		if !ok {
			v, err = ast.InterfaceToValue(blob)
			if err != nil {
				return nil, err
			}
		}
	}

	e.baseCache.Put(ref, v)
	if a == nil {
		return v, nil
	}

	merged, ok := merge(a, v)
	if !ok {
		return nil, mergeConflictErr(ref[0].Location)
	}

	return merged, nil
}

func (e *eval) generateVar(suffix string) *ast.Term {
	return ast.VarTerm(fmt.Sprintf("%v_%v", e.genvarprefix, suffix))
}

func (e *eval) rewrittenVar(v ast.Var) (ast.Var, bool) {
	if e.compiler != nil {
		if rw, ok := e.compiler.RewrittenVars[v]; ok {
			return rw, true
		}
	}
	if e.queryCompiler != nil {
		if rw, ok := e.queryCompiler.RewrittenVars()[v]; ok {
			return rw, true
		}
	}
	return v, false
}

func (e *eval) getDeclArgsLen(x *ast.Expr) (int, error) {

	if !x.IsCall() {
		return -1, nil
	}

	operator := x.Operator()
	bi, _, ok := e.builtinFunc(operator.String())

	if ok {
		return len(bi.Decl.Args()), nil
	}

	ir, err := e.getRules(operator, nil)
	if err != nil {
		return -1, err
	} else if ir == nil || ir.Empty() {
		return -1, nil
	}

	return len(ir.Rules[0].Head.Args), nil
}

type evalBuiltin struct {
	e     *eval
	bi    *ast.Builtin
	bctx  BuiltinContext
	f     BuiltinFunc
	terms []*ast.Term
}

func (e evalBuiltin) eval(iter unifyIterator) error {

	operands := make([]*ast.Term, len(e.terms))

	for i := 0; i < len(e.terms); i++ {
		operands[i] = e.e.bindings.Plug(e.terms[i])
	}

	numDeclArgs := len(e.bi.Decl.FuncArgs().Args)

	e.e.instr.startTimer(evalOpBuiltinCall)

	err := e.f(e.bctx, operands, func(output *ast.Term) error {

		e.e.instr.stopTimer(evalOpBuiltinCall)

		var err error

		if e.bi.Decl.Result() == nil {
			err = iter()
		} else if len(operands) == numDeclArgs {
			if output.Value.Compare(ast.Boolean(false)) != 0 {
				err = iter()
			}
		} else {
			err = e.e.unify(e.terms[len(e.terms)-1], output, iter)
		}

		if err != nil {
			err = Halt{Err: err}
		}

		e.e.instr.startTimer(evalOpBuiltinCall)
		return err
	})

	if err != nil {
		if t, ok := err.(Halt); ok {
			err = t.Err
		} else {
			e.e.builtinErrors.errs = append(e.e.builtinErrors.errs, err)
			err = nil
		}
	}

	e.e.instr.stopTimer(evalOpBuiltinCall)
	return err
}

type evalFunc struct {
	e     *eval
	ref   ast.Ref
	terms []*ast.Term
	ir    *ast.IndexResult
}

func (e evalFunc) eval(iter unifyIterator) error {

	// default functions aren't supported:
	// https://github.com/open-policy-agent/opa/issues/2445
	if len(e.ir.Rules) == 0 {
		return nil
	}

	argCount := len(e.ir.Rules[0].Head.Args)

	if len(e.ir.Else) > 0 && e.e.unknown(e.e.query[e.e.index], e.e.bindings) {
		// Partial evaluation of ordered rules is not supported currently. Save the
		// expression and continue. This could be revisited in the future.
		return e.e.saveCall(argCount, e.terms, iter)
	}

	if e.e.partial() && (e.e.inliningControl.shallow || e.e.inliningControl.Disabled(e.ref, false)) {
		// check if the function definitions, or any of the arguments
		// contain something unknown
		unknown := e.e.unknown(e.ref, e.e.bindings)
		for i := 1; !unknown && i <= argCount; i++ {
			unknown = e.e.unknown(e.terms[i], e.e.bindings)
		}
		if unknown {
			return e.partialEvalSupport(argCount, iter)
		}
	}
	return suppressEarlyExit(e.evalValue(iter, argCount, e.ir.EarlyExit))
}

func (e evalFunc) evalValue(iter unifyIterator, argCount int, findOne bool) error {
	var cacheKey ast.Ref
	var hit bool
	var err error
	if !e.e.partial() {
		cacheKey, hit, err = e.evalCache(argCount, iter)
		if err != nil {
			return err
		} else if hit {
			return nil
		}
	}

	var prev *ast.Term

	for _, rule := range e.ir.Rules {
		next, err := e.evalOneRule(iter, rule, cacheKey, prev, findOne)
		if err != nil {
			return err
		}
		if next == nil {
			for _, erule := range e.ir.Else[rule] {
				next, err = e.evalOneRule(iter, erule, cacheKey, prev, findOne)
				if err != nil {
					return err
				}
				if next != nil {
					break
				}
			}
		}
		if next != nil {
			prev = next
		}
	}

	return nil
}

func (e evalFunc) evalCache(argCount int, iter unifyIterator) (ast.Ref, bool, error) {
	var plen int
	if len(e.terms) == argCount+2 { // func name + output = 2
		plen = len(e.terms) - 1
	} else {
		plen = len(e.terms)
	}
	cacheKey := make([]*ast.Term, plen)
	for i := 0; i < plen; i++ {
		cacheKey[i] = e.e.bindings.Plug(e.terms[i])
	}

	cached := e.e.virtualCache.Get(cacheKey)
	if cached != nil {
		e.e.instr.counterIncr(evalOpVirtualCacheHit)
		if argCount == len(e.terms)-1 { // f(x)
			if ast.Boolean(false).Equal(cached.Value) {
				return nil, true, nil
			}
			return nil, true, iter()
		}
		// f(x, y), y captured output value
		return nil, true, e.e.unify(e.terms[len(e.terms)-1] /* y */, cached, iter)
	}
	e.e.instr.counterIncr(evalOpVirtualCacheMiss)
	return cacheKey, false, nil
}

func (e evalFunc) evalOneRule(iter unifyIterator, rule *ast.Rule, cacheKey ast.Ref, prev *ast.Term, findOne bool) (*ast.Term, error) {

	child := e.e.child(rule.Body)
	child.findOne = findOne

	args := make([]*ast.Term, len(e.terms)-1)
	copy(args, rule.Head.Args)

	if len(args) == len(rule.Head.Args)+1 {
		args[len(args)-1] = rule.Head.Value
	}

	var result *ast.Term

	child.traceEnter(rule)

	err := child.biunifyArrays(ast.NewArray(e.terms[1:]...), ast.NewArray(args...), e.e.bindings, child.bindings, func() error {
		return child.eval(func(child *eval) error {
			child.traceExit(rule)

			// Partial evaluation must save an expression that tests the output value if the output value
			// was not captured to handle the case where the output value may be `false`.
			if len(rule.Head.Args) == len(e.terms)-1 && e.e.saveSet.Contains(rule.Head.Value, child.bindings) {
				err := e.e.saveExpr(ast.NewExpr(rule.Head.Value), child.bindings, iter)
				child.traceRedo(rule)
				return err
			}

			result = child.bindings.Plug(rule.Head.Value)
			if cacheKey != nil {
				e.e.virtualCache.Put(cacheKey, result) // the redos confirm this, or the evaluation is aborted
			}

			if len(rule.Head.Args) == len(e.terms)-1 {
				if result.Value.Compare(ast.Boolean(false)) == 0 {
					if prev != nil && ast.Compare(prev, result) != 0 {
						return functionConflictErr(rule.Location)
					}
					return nil
				}
			}

			// Partial evaluation should explore all rules and may not produce
			// a ground result so we do not perform conflict detection or
			// deduplication. See "ignore conflicts: functions" test case for
			// an example.
			if !e.e.partial() {
				if prev != nil {
					if ast.Compare(prev, result) != 0 {
						return functionConflictErr(rule.Location)
					}
					child.traceRedo(rule)
					return nil
				}
			}

			prev = result

			if err := iter(); err != nil {
				return err
			}

			child.traceRedo(rule)
			return nil
		})
	})

	return result, err
}

func (e evalFunc) partialEvalSupport(declArgsLen int, iter unifyIterator) error {

	path := e.e.namespaceRef(e.ref)
	term := ast.NewTerm(path)

	if !e.e.saveSupport.Exists(path) {
		for _, rule := range e.ir.Rules {
			err := e.partialEvalSupportRule(rule, path)
			if err != nil {
				return err
			}
		}
	}

	if !e.e.saveSupport.Exists(path) { // we haven't saved anything, nothing to call
		return nil
	}

	return e.e.saveCall(declArgsLen, append([]*ast.Term{term}, e.terms[1:]...), iter)
}

func (e evalFunc) partialEvalSupportRule(rule *ast.Rule, path ast.Ref) error {

	child := e.e.child(rule.Body)
	child.traceEnter(rule)

	e.e.saveStack.PushQuery(nil)

	// treat the function arguments as unknown during rule body evaluation
	var args []*ast.Term
	ast.WalkVars(rule.Head.Args, func(v ast.Var) bool {
		args = append(args, ast.VarTerm(string(v)))
		return false
	})
	e.e.saveSet.Push(args, child.bindings)

	err := child.eval(func(child *eval) error {
		child.traceExit(rule)

		current := e.e.saveStack.PopQuery()
		plugged := current.Plug(e.e.caller.bindings)

		// Skip this rule body if it fails to type-check.
		// Type-checking failure means the rule body will never succeed.
		if e.e.compiler.PassesTypeCheck(plugged) {
			head := &ast.Head{
				Name:  rule.Head.Name,
				Value: child.bindings.PlugNamespaced(rule.Head.Value, e.e.caller.bindings),
				Args:  make([]*ast.Term, len(rule.Head.Args)),
			}
			for i, a := range rule.Head.Args {
				head.Args[i] = child.bindings.PlugNamespaced(a, e.e.caller.bindings)
			}

			e.e.saveSupport.Insert(path, &ast.Rule{
				Head: head,
				Body: plugged,
			})
		}
		child.traceRedo(rule)
		e.e.saveStack.PushQuery(current)
		return nil
	})

	e.e.saveSet.Pop()
	e.e.saveStack.PopQuery()
	return err
}

type evalTree struct {
	e         *eval
	ref       ast.Ref
	plugged   ast.Ref
	pos       int
	bindings  *bindings
	rterm     *ast.Term
	rbindings *bindings
	node      *ast.TreeNode
}

func (e evalTree) eval(iter unifyIterator) error {

	if len(e.ref) == e.pos {
		return e.finish(iter)
	}

	plugged := e.bindings.Plug(e.ref[e.pos])

	if plugged.IsGround() {
		return e.next(iter, plugged)
	}

	return e.enumerate(iter)
}

func (e evalTree) finish(iter unifyIterator) error {

	// In some cases, it may not be possible to PE the ref. If the path refers
	// to virtual docs that PE does not support or base documents where inlining
	// has been disabled, then we have to save.
	save := e.e.unknown(e.plugged, e.e.bindings)

	if save {
		return e.e.saveUnify(ast.NewTerm(e.plugged), e.rterm, e.bindings, e.rbindings, iter)
	}

	v, err := e.extent()
	if err != nil || v == nil {
		return err
	}

	return e.e.biunify(e.rterm, v, e.rbindings, e.bindings, iter)
}

func (e evalTree) next(iter unifyIterator, plugged *ast.Term) error {

	var node *ast.TreeNode

	cpy := e
	cpy.plugged[e.pos] = plugged
	cpy.pos++

	if !e.e.targetStack.Prefixed(cpy.plugged[:cpy.pos]) {
		if e.node != nil {
			node = e.node.Child(plugged.Value)
			if node != nil && len(node.Values) > 0 {
				r := evalVirtual{
					e:         e.e,
					ref:       e.ref,
					plugged:   e.plugged,
					pos:       e.pos,
					bindings:  e.bindings,
					rterm:     e.rterm,
					rbindings: e.rbindings,
				}
				r.plugged[e.pos] = plugged
				return r.eval(iter)
			}
		}
	}

	cpy.node = node
	return cpy.eval(iter)
}

func (e evalTree) enumerate(iter unifyIterator) error {

	if e.e.inliningControl.Disabled(e.plugged[:e.pos], true) {
		return e.e.saveUnify(ast.NewTerm(e.plugged), e.rterm, e.bindings, e.rbindings, iter)
	}

	doc, err := e.e.Resolve(e.plugged[:e.pos])
	if err != nil {
		return err
	}

	if doc != nil {
		switch doc := doc.(type) {
		case *ast.Array:
			for i := 0; i < doc.Len(); i++ {
				k := ast.IntNumberTerm(i)
				err := e.e.biunify(k, e.ref[e.pos], e.bindings, e.bindings, func() error {
					return e.next(iter, k)
				})
				if err != nil {
					return err
				}
			}
		case ast.Object:
			err := doc.Iter(func(k, _ *ast.Term) error {
				return e.e.biunify(k, e.ref[e.pos], e.bindings, e.bindings, func() error {
					return e.next(iter, k)
				})
			})
			if err != nil {
				return err
			}
		case ast.Set:
			err := doc.Iter(func(elem *ast.Term) error {
				return e.e.biunify(elem, e.ref[e.pos], e.bindings, e.bindings, func() error {
					return e.next(iter, elem)
				})
			})
			if err != nil {
				return err
			}
		}
	}

	if e.node == nil {
		return nil
	}

	for _, k := range e.node.Sorted {
		key := ast.NewTerm(k)
		if err := e.e.biunify(key, e.ref[e.pos], e.bindings, e.bindings, func() error {
			return e.next(iter, key)
		}); err != nil {
			return err
		}
	}

	return nil
}

func (e evalTree) extent() (*ast.Term, error) {
	base, err := e.e.Resolve(e.plugged)
	if err != nil {
		return nil, err
	}

	virtual, err := e.leaves(e.plugged, e.node)
	if err != nil {
		return nil, err
	}

	if virtual == nil {
		if base == nil {
			return nil, nil
		}
		return ast.NewTerm(base), nil
	}

	if base != nil {
		merged, ok := merge(base, virtual)
		if !ok {
			return nil, mergeConflictErr(e.plugged[0].Location)
		}
		return ast.NewTerm(merged), nil
	}

	return ast.NewTerm(virtual), nil
}

func (e evalTree) leaves(plugged ast.Ref, node *ast.TreeNode) (ast.Object, error) {

	if e.node == nil {
		return nil, nil
	}

	result := ast.NewObject()

	for _, k := range node.Sorted {

		child := node.Children[k]

		if child.Hide {
			continue
		}

		plugged = append(plugged, ast.NewTerm(child.Key))

		var save ast.Value
		var err error

		if len(child.Values) > 0 {
			rterm := e.e.generateVar("leaf")
			err = e.e.unify(ast.NewTerm(plugged), rterm, func() error {
				save = e.e.bindings.Plug(rterm).Value
				return nil
			})
		} else {
			save, err = e.leaves(plugged, child)
		}

		if err != nil {
			return nil, err
		}

		if save != nil {
			v := ast.NewObject([2]*ast.Term{plugged[len(plugged)-1], ast.NewTerm(save)})
			result, _ = result.Merge(v)
		}

		plugged = plugged[:len(plugged)-1]
	}

	return result, nil
}

type evalVirtual struct {
	e         *eval
	ref       ast.Ref
	plugged   ast.Ref
	pos       int
	bindings  *bindings
	rterm     *ast.Term
	rbindings *bindings
}

func (e evalVirtual) eval(iter unifyIterator) error {

	ir, err := e.e.getRules(e.plugged[:e.pos+1], nil)
	if err != nil {
		return err
	}

	// Partial evaluation of ordered rules is not supported currently. Save the
	// expression and continue. This could be revisited in the future.
	if len(ir.Else) > 0 && e.e.unknown(e.ref, e.bindings) {
		return e.e.saveUnify(ast.NewTerm(e.ref), e.rterm, e.bindings, e.rbindings, iter)
	}

	switch ir.Kind {
	case ast.PartialSetDoc:
		eval := evalVirtualPartial{
			e:         e.e,
			ref:       e.ref,
			plugged:   e.plugged,
			pos:       e.pos,
			ir:        ir,
			bindings:  e.bindings,
			rterm:     e.rterm,
			rbindings: e.rbindings,
			empty:     ast.SetTerm(),
		}
		return eval.eval(iter)
	case ast.PartialObjectDoc:
		eval := evalVirtualPartial{
			e:         e.e,
			ref:       e.ref,
			plugged:   e.plugged,
			pos:       e.pos,
			ir:        ir,
			bindings:  e.bindings,
			rterm:     e.rterm,
			rbindings: e.rbindings,
			empty:     ast.ObjectTerm(),
		}
		return eval.eval(iter)
	default:
		eval := evalVirtualComplete{
			e:         e.e,
			ref:       e.ref,
			plugged:   e.plugged,
			pos:       e.pos,
			ir:        ir,
			bindings:  e.bindings,
			rterm:     e.rterm,
			rbindings: e.rbindings,
		}
		return eval.eval(iter)
	}
}

type evalVirtualPartial struct {
	e         *eval
	ref       ast.Ref
	plugged   ast.Ref
	pos       int
	ir        *ast.IndexResult
	bindings  *bindings
	rterm     *ast.Term
	rbindings *bindings
	empty     *ast.Term
}

type evalVirtualPartialCacheHint struct {
	key  ast.Ref
	hit  bool
	full bool
}

func (e evalVirtualPartial) eval(iter unifyIterator) error {

	unknown := e.e.unknown(e.ref[:e.pos+1], e.bindings)

	if len(e.ref) == e.pos+1 {
		if unknown {
			return e.partialEvalSupport(iter)
		}
		return e.evalAllRules(iter, e.ir.Rules)
	}

	if (unknown && e.e.inliningControl.shallow) || e.e.inliningControl.Disabled(e.ref[:e.pos+1], false) {
		return e.partialEvalSupport(iter)
	}

	return e.evalEachRule(iter, unknown)
}

func (e evalVirtualPartial) evalEachRule(iter unifyIterator, unknown bool) error {

	if e.e.unknown(e.ref[e.pos+1], e.bindings) {
		for _, rule := range e.ir.Rules {
			if err := e.evalOneRulePostUnify(iter, rule); err != nil {
				return err
			}
		}
		return nil
	}

	hint, err := e.evalCache(iter)
	if err != nil {
		return err
	} else if hint.hit {
		return nil
	}

	if hint.full {
		result, err := e.evalAllRulesNoCache(e.ir.Rules)
		if err != nil {
			return err
		}
		e.e.virtualCache.Put(hint.key, result)
		return e.evalTerm(iter, e.pos+1, result, e.bindings)
	}

	result := e.empty
	for _, rule := range e.ir.Rules {
		if err := e.evalOneRulePreUnify(iter, rule, hint, result, unknown); err != nil {
			return err
		}
	}

	return nil
}

func (e evalVirtualPartial) evalAllRules(iter unifyIterator, rules []*ast.Rule) error {

	cacheKey := e.plugged[:e.pos+1]
	result := e.e.virtualCache.Get(cacheKey)
	if result != nil {
		e.e.instr.counterIncr(evalOpVirtualCacheHit)
		return e.e.biunify(result, e.rterm, e.bindings, e.rbindings, iter)
	}

	e.e.instr.counterIncr(evalOpVirtualCacheMiss)

	result, err := e.evalAllRulesNoCache(rules)
	if err != nil {
		return err
	}

	if cacheKey != nil {
		e.e.virtualCache.Put(cacheKey, result)
	}

	return e.e.biunify(result, e.rterm, e.bindings, e.rbindings, iter)
}

func (e evalVirtualPartial) evalAllRulesNoCache(rules []*ast.Rule) (*ast.Term, error) {
	result := e.empty

	for _, rule := range rules {
		child := e.e.child(rule.Body)
		child.traceEnter(rule)
		err := child.eval(func(*eval) error {
			child.traceExit(rule)
			var err error
			result, _, err = e.reduce(rule.Head, child.bindings, result)
			if err != nil {
				return err
			}

			child.traceRedo(rule)
			return nil
		})

		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func (e evalVirtualPartial) evalOneRulePreUnify(iter unifyIterator, rule *ast.Rule, hint evalVirtualPartialCacheHint, result *ast.Term, unknown bool) error {

	key := e.ref[e.pos+1]
	child := e.e.child(rule.Body)

	child.traceEnter(rule)
	var defined bool

	err := child.biunify(rule.Head.Key, key, child.bindings, e.bindings, func() error {
		defined = true
		return child.eval(func(child *eval) error {

			term := rule.Head.Value
			if term == nil {
				term = rule.Head.Key
			}

			if hint.key != nil {
				result := child.bindings.Plug(term)
				e.e.virtualCache.Put(hint.key, result)
			}

			// NOTE(tsandall): if the rule set depends on any unknowns then do
			// not perform the duplicate check because evaluation of the ruleset
			// may not produce a definitive result. This is a bit strict--we
			// could improve by skipping only when saves occur.
			if !unknown {
				var dup bool
				var err error
				result, dup, err = e.reduce(rule.Head, child.bindings, result)
				if err != nil {
					return err
				} else if dup {
					child.traceDuplicate(rule)
					return nil
				}
			}

			child.traceExit(rule)
			term, termbindings := child.bindings.apply(term)
			err := e.evalTerm(iter, e.pos+2, term, termbindings)
			if err != nil {
				return err
			}

			child.traceRedo(rule)
			return nil
		})
	})

	if err != nil {
		return err
	}

	// TODO(tsandall): why are we tracing here? this looks wrong.
	if !defined {
		child.traceFail(rule)
	}

	return nil
}

func (e evalVirtualPartial) evalOneRulePostUnify(iter unifyIterator, rule *ast.Rule) error {

	key := e.ref[e.pos+1]
	child := e.e.child(rule.Body)

	child.traceEnter(rule)
	var defined bool

	err := child.eval(func(child *eval) error {
		defined = true
		return e.e.biunify(rule.Head.Key, key, child.bindings, e.bindings, func() error {
			return e.evalOneRuleContinue(iter, rule, child)
		})
	})

	if err != nil {
		return err
	}

	if !defined {
		child.traceFail(rule)
	}

	return nil
}

func (e evalVirtualPartial) evalOneRuleContinue(iter unifyIterator, rule *ast.Rule, child *eval) error {

	child.traceExit(rule)

	term := rule.Head.Value
	if term == nil {
		term = rule.Head.Key
	}

	term, termbindings := child.bindings.apply(term)
	err := e.evalTerm(iter, e.pos+2, term, termbindings)
	if err != nil {
		return err
	}

	child.traceRedo(rule)
	return nil
}

func (e evalVirtualPartial) partialEvalSupport(iter unifyIterator) error {

	path := e.e.namespaceRef(e.plugged[:e.pos+1])
	term := ast.NewTerm(e.e.namespaceRef(e.ref))

	var defined bool

	if e.e.saveSupport.Exists(path) {
		defined = true
	} else {
		for i := range e.ir.Rules {
			ok, err := e.partialEvalSupportRule(e.ir.Rules[i], path)
			if err != nil {
				return err
			} else if ok {
				defined = true
			}
		}
	}

	if !defined {
		if len(e.ref) != e.pos+1 {
			return nil
		}

		// the entire partial set/obj was queried, e.g. data.a.q (not data.a.q[x])
		term = e.empty
	}

	return e.e.saveUnify(term, e.rterm, e.bindings, e.rbindings, iter)
}

func (e evalVirtualPartial) partialEvalSupportRule(rule *ast.Rule, path ast.Ref) (bool, error) {

	child := e.e.child(rule.Body)
	child.traceEnter(rule)

	e.e.saveStack.PushQuery(nil)
	var defined bool

	err := child.eval(func(child *eval) error {
		child.traceExit(rule)
		defined = true

		current := e.e.saveStack.PopQuery()
		plugged := current.Plug(e.e.caller.bindings)
		// Skip this rule body if it fails to type-check.
		// Type-checking failure means the rule body will never succeed.
		if e.e.compiler.PassesTypeCheck(plugged) {
			var key, value *ast.Term

			if rule.Head.Key != nil {
				key = child.bindings.PlugNamespaced(rule.Head.Key, e.e.caller.bindings)
			}

			if rule.Head.Value != nil {
				value = child.bindings.PlugNamespaced(rule.Head.Value, e.e.caller.bindings)
			}

			head := ast.NewHead(rule.Head.Name, key, value)

			if !e.e.inliningControl.shallow {
				cp := copypropagation.New(head.Vars()).
					WithEnsureNonEmptyBody(true).
					WithCompiler(e.e.compiler)
				plugged = applyCopyPropagation(cp, e.e.instr, plugged)
			}

			e.e.saveSupport.Insert(path, &ast.Rule{
				Head:    head,
				Body:    plugged,
				Default: rule.Default,
			})
		}
		child.traceRedo(rule)
		e.e.saveStack.PushQuery(current)
		return nil
	})
	e.e.saveStack.PopQuery()
	return defined, err
}

func (e evalVirtualPartial) evalTerm(iter unifyIterator, pos int, term *ast.Term, termbindings *bindings) error {
	eval := evalTerm{
		e:            e.e,
		ref:          e.ref,
		pos:          pos,
		bindings:     e.bindings,
		term:         term,
		termbindings: termbindings,
		rterm:        e.rterm,
		rbindings:    e.rbindings,
	}
	return eval.eval(iter)
}

func (e evalVirtualPartial) evalCache(iter unifyIterator) (evalVirtualPartialCacheHint, error) {

	var hint evalVirtualPartialCacheHint

	if e.e.unknown(e.ref[:e.pos+1], e.bindings) {
		return hint, nil
	}

	if cached := e.e.virtualCache.Get(e.plugged[:e.pos+1]); cached != nil { // have full extent cached
		e.e.instr.counterIncr(evalOpVirtualCacheHit)
		hint.hit = true
		return hint, e.evalTerm(iter, e.pos+1, cached, e.bindings)
	}

	plugged := e.bindings.Plug(e.ref[e.pos+1])

	if plugged.IsGround() {
		hint.key = append(e.plugged[:e.pos+1], plugged)

		if cached := e.e.virtualCache.Get(hint.key); cached != nil {
			e.e.instr.counterIncr(evalOpVirtualCacheHit)
			hint.hit = true
			return hint, e.evalTerm(iter, e.pos+2, cached, e.bindings)
		}
	} else if _, ok := plugged.Value.(ast.Var); ok {
		hint.full = true
		hint.key = e.plugged[:e.pos+1]
	}

	e.e.instr.counterIncr(evalOpVirtualCacheMiss)

	return hint, nil
}

func (e evalVirtualPartial) reduce(head *ast.Head, b *bindings, result *ast.Term) (*ast.Term, bool, error) {

	var exists bool
	key := b.Plug(head.Key)

	switch v := result.Value.(type) {
	case ast.Set:
		exists = v.Contains(key)
		v.Add(key)
	case ast.Object:
		value := b.Plug(head.Value)
		if curr := v.Get(key); curr != nil {
			if !curr.Equal(value) {
				return nil, false, objectDocKeyConflictErr(head.Location)
			}
			exists = true
		} else {
			v.Insert(key, value)
		}
	}

	return result, exists, nil
}

type evalVirtualComplete struct {
	e         *eval
	ref       ast.Ref
	plugged   ast.Ref
	pos       int
	ir        *ast.IndexResult
	bindings  *bindings
	rterm     *ast.Term
	rbindings *bindings
}

func (e evalVirtualComplete) eval(iter unifyIterator) error {

	if e.ir.Empty() {
		return nil
	}

	if len(e.ir.Rules) > 0 && len(e.ir.Rules[0].Head.Args) > 0 {
		return nil
	}

	if !e.e.unknown(e.ref, e.bindings) {
		return suppressEarlyExit(e.evalValue(iter, e.ir.EarlyExit))
	}

	var generateSupport bool

	if e.ir.Default != nil {
		// If the other term is not constant OR it's equal to the default value, then
		// a support rule must be produced as the default value _may_ be required. On
		// the other hand, if the other term is constant (i.e., it does not require
		// evaluation) and it differs from the default value then the default value is
		// _not_ required, so partially evaluate the rule normally.
		rterm := e.rbindings.Plug(e.rterm)
		generateSupport = !ast.IsConstant(rterm.Value) || e.ir.Default.Head.Value.Equal(rterm)
	}

	if generateSupport || e.e.inliningControl.shallow || e.e.inliningControl.Disabled(e.plugged[:e.pos+1], false) {
		return e.partialEvalSupport(iter)
	}

	return e.partialEval(iter)
}

func (e evalVirtualComplete) evalValue(iter unifyIterator, findOne bool) error {
	cached := e.e.virtualCache.Get(e.plugged[:e.pos+1])
	if cached != nil {
		e.e.instr.counterIncr(evalOpVirtualCacheHit)
		return e.evalTerm(iter, cached, e.bindings)
	}

	e.e.instr.counterIncr(evalOpVirtualCacheMiss)

	var prev *ast.Term

	for _, rule := range e.ir.Rules {
		next, err := e.evalValueRule(iter, rule, prev, findOne)
		if err != nil {
			return err
		}
		if next == nil {
			for _, erule := range e.ir.Else[rule] {
				next, err = e.evalValueRule(iter, erule, prev, findOne)
				if err != nil {
					return err
				}
				if next != nil {
					break
				}
			}
		}
		if next != nil {
			prev = next
		}
	}

	if e.ir.Default != nil && prev == nil {
		_, err := e.evalValueRule(iter, e.ir.Default, prev, findOne)
		return err
	}

	return nil
}

func (e evalVirtualComplete) evalValueRule(iter unifyIterator, rule *ast.Rule, prev *ast.Term, findOne bool) (*ast.Term, error) {

	child := e.e.child(rule.Body)
	child.findOne = findOne
	child.traceEnter(rule)
	var result *ast.Term
	err := child.eval(func(child *eval) error {
		child.traceExit(rule)
		result = child.bindings.Plug(rule.Head.Value)

		if prev != nil {
			if ast.Compare(result, prev) != 0 {
				return completeDocConflictErr(rule.Location)
			}
			child.traceRedo(rule)
			return nil
		}

		prev = result
		e.e.virtualCache.Put(e.plugged[:e.pos+1], result)
		term, termbindings := child.bindings.apply(rule.Head.Value)

		err := e.evalTerm(iter, term, termbindings)
		if err != nil {
			return err
		}

		child.traceRedo(rule)
		return nil
	})

	return result, err
}

func (e evalVirtualComplete) partialEval(iter unifyIterator) error {

	for _, rule := range e.ir.Rules {
		child := e.e.child(rule.Body)
		child.traceEnter(rule)

		err := child.eval(func(child *eval) error {
			child.traceExit(rule)
			term, termbindings := child.bindings.apply(rule.Head.Value)

			err := e.evalTerm(iter, term, termbindings)
			if err != nil {
				return err
			}

			child.traceRedo(rule)
			return nil
		})

		if err != nil {
			return err
		}
	}

	return nil
}

func (e evalVirtualComplete) partialEvalSupport(iter unifyIterator) error {

	path := e.e.namespaceRef(e.plugged[:e.pos+1])
	term := ast.NewTerm(e.e.namespaceRef(e.ref))

	if !e.e.saveSupport.Exists(path) {

		for i := range e.ir.Rules {
			err := e.partialEvalSupportRule(e.ir.Rules[i], path)
			if err != nil {
				return err
			}
		}

		if e.ir.Default != nil {
			err := e.partialEvalSupportRule(e.ir.Default, path)
			if err != nil {
				return err
			}
		}
	}

	return e.e.saveUnify(term, e.rterm, e.bindings, e.rbindings, iter)
}

func (e evalVirtualComplete) partialEvalSupportRule(rule *ast.Rule, path ast.Ref) error {

	child := e.e.child(rule.Body)
	child.traceEnter(rule)

	e.e.saveStack.PushQuery(nil)

	err := child.eval(func(child *eval) error {
		child.traceExit(rule)

		current := e.e.saveStack.PopQuery()
		plugged := current.Plug(e.e.caller.bindings)
		// Skip this rule body if it fails to type-check.
		// Type-checking failure means the rule body will never succeed.
		if e.e.compiler.PassesTypeCheck(plugged) {
			head := ast.NewHead(rule.Head.Name, nil, child.bindings.PlugNamespaced(rule.Head.Value, e.e.caller.bindings))

			if !e.e.inliningControl.shallow {
				cp := copypropagation.New(head.Vars()).
					WithEnsureNonEmptyBody(true).
					WithCompiler(e.e.compiler)
				plugged = applyCopyPropagation(cp, e.e.instr, plugged)
			}

			e.e.saveSupport.Insert(path, &ast.Rule{
				Head:    head,
				Body:    plugged,
				Default: rule.Default,
			})
		}
		child.traceRedo(rule)
		e.e.saveStack.PushQuery(current)
		return nil
	})
	e.e.saveStack.PopQuery()
	return err
}

func (e evalVirtualComplete) evalTerm(iter unifyIterator, term *ast.Term, termbindings *bindings) error {
	eval := evalTerm{
		e:            e.e,
		ref:          e.ref,
		pos:          e.pos + 1,
		bindings:     e.bindings,
		term:         term,
		termbindings: termbindings,
		rterm:        e.rterm,
		rbindings:    e.rbindings,
	}
	return eval.eval(iter)
}

type evalTerm struct {
	e            *eval
	ref          ast.Ref
	pos          int
	bindings     *bindings
	term         *ast.Term
	termbindings *bindings
	rterm        *ast.Term
	rbindings    *bindings
}

func (e evalTerm) eval(iter unifyIterator) error {

	if len(e.ref) == e.pos {
		return e.e.biunify(e.term, e.rterm, e.termbindings, e.rbindings, iter)
	}

	if e.e.saveSet.Contains(e.term, e.termbindings) {
		return e.save(iter)
	}

	plugged := e.bindings.Plug(e.ref[e.pos])

	if plugged.IsGround() {
		return e.next(iter, plugged)
	}

	return e.enumerate(iter)
}

func (e evalTerm) next(iter unifyIterator, plugged *ast.Term) error {

	term, bindings := e.get(plugged)
	if term == nil {
		return nil
	}

	cpy := e
	cpy.term = term
	cpy.termbindings = bindings
	cpy.pos++
	return cpy.eval(iter)
}

func (e evalTerm) enumerate(iter unifyIterator) error {

	switch v := e.term.Value.(type) {
	case *ast.Array:
		for i := 0; i < v.Len(); i++ {
			k := ast.IntNumberTerm(i)
			err := e.e.biunify(k, e.ref[e.pos], e.bindings, e.bindings, func() error {
				return e.next(iter, k)
			})
			if err != nil {
				return err
			}
		}
	case ast.Object:
		return v.Iter(func(k, _ *ast.Term) error {
			return e.e.biunify(k, e.ref[e.pos], e.termbindings, e.bindings, func() error {
				return e.next(iter, e.termbindings.Plug(k))
			})
		})
	case ast.Set:
		return v.Iter(func(elem *ast.Term) error {
			return e.e.biunify(elem, e.ref[e.pos], e.termbindings, e.bindings, func() error {
				return e.next(iter, e.termbindings.Plug(elem))
			})
		})
	}

	return nil
}

func (e evalTerm) get(plugged *ast.Term) (*ast.Term, *bindings) {
	switch v := e.term.Value.(type) {
	case ast.Set:
		if v.IsGround() {
			if v.Contains(plugged) {
				return e.termbindings.apply(plugged)
			}
		} else {
			var t *ast.Term
			var b *bindings
			stop := v.Until(func(elem *ast.Term) bool {
				if e.termbindings.Plug(elem).Equal(plugged) {
					t, b = e.termbindings.apply(plugged)
					return true
				}
				return false
			})
			if stop {
				return t, b
			}
		}
	case ast.Object:
		if v.IsGround() {
			term := v.Get(plugged)
			if term != nil {
				return e.termbindings.apply(term)
			}
		} else {
			var t *ast.Term
			var b *bindings
			stop := v.Until(func(k, v *ast.Term) bool {
				if e.termbindings.Plug(k).Equal(plugged) {
					t, b = e.termbindings.apply(v)
					return true
				}
				return false
			})
			if stop {
				return t, b
			}
		}
	case *ast.Array:
		term := v.Get(plugged)
		if term != nil {
			return e.termbindings.apply(term)
		}
	}
	return nil, nil
}

func (e evalTerm) save(iter unifyIterator) error {

	v := e.e.generateVar(fmt.Sprintf("ref_%d", e.e.genvarid))
	e.e.genvarid++

	return e.e.biunify(e.term, v, e.termbindings, e.bindings, func() error {

		suffix := e.ref[e.pos:]
		ref := make(ast.Ref, len(suffix)+1)
		ref[0] = v
		for i := 0; i < len(suffix); i++ {
			ref[i+1] = suffix[i]
		}

		return e.e.biunify(ast.NewTerm(ref), e.rterm, e.bindings, e.rbindings, iter)
	})

}

func (e *eval) comprehensionIndex(term *ast.Term) *ast.ComprehensionIndex {
	if e.queryCompiler != nil {
		return e.queryCompiler.ComprehensionIndex(term)
	}
	return e.compiler.ComprehensionIndex(term)
}

func (e *eval) namespaceRef(ref ast.Ref) ast.Ref {
	if e.skipSaveNamespace {
		return ref.Copy()
	}
	return ref.Insert(e.saveNamespace, 1)
}

type savePair struct {
	term *ast.Term
	b    *bindings
}

func getSavePairsFromExpr(declArgsLen int, x *ast.Expr, b *bindings, result []savePair) []savePair {
	switch terms := x.Terms.(type) {
	case *ast.Term:
		return getSavePairsFromTerm(terms, b, result)
	case []*ast.Term:
		if x.IsEquality() {
			return getSavePairsFromTerm(terms[2], b, getSavePairsFromTerm(terms[1], b, result))
		}
		if declArgsLen == len(terms)-2 {
			return getSavePairsFromTerm(terms[len(terms)-1], b, result)
		}
	}
	return result
}

func getSavePairsFromTerm(x *ast.Term, b *bindings, result []savePair) []savePair {
	if _, ok := x.Value.(ast.Var); ok {
		result = append(result, savePair{x, b})
		return result
	}
	vis := ast.NewVarVisitor().WithParams(ast.VarVisitorParams{
		SkipClosures: true,
		SkipRefHead:  true,
	})
	vis.Walk(x)
	for v := range vis.Vars() {
		y, next := b.apply(ast.NewTerm(v))
		result = getSavePairsFromTerm(y, next, result)
	}
	return result
}

func applyCopyPropagation(p *copypropagation.CopyPropagator, instr *Instrumentation, body ast.Body) ast.Body {
	instr.startTimer(partialOpCopyPropagation)
	result := p.Apply(body)
	instr.stopTimer(partialOpCopyPropagation)
	return result
}

func nonGroundKeys(a ast.Object) bool {
	return a.Until(func(k, _ *ast.Term) bool {
		return !k.IsGround()
	})
}

func plugKeys(a ast.Object, b *bindings) ast.Object {
	plugged, _ := a.Map(func(k, v *ast.Term) (*ast.Term, *ast.Term, error) {
		return b.Plug(k), v, nil
	})
	return plugged
}

func canInlineNegation(safe ast.VarSet, queries []ast.Body) bool {

	size := 1
	vis := newNestedCheckVisitor()

	for _, query := range queries {
		size *= len(query)
		for _, expr := range query {
			if containsNestedRefOrCall(vis, expr) {
				// Expressions containing nested refs or calls cannot be trivially negated
				// because the semantics would change. For example, the complement of `not f(input.x)`
				// is _not_ `f(input.x)`--it is `not input.x` OR `f(input.x)`.
				//
				// NOTE(tsandall): Since this would require the complement function to undo the
				// copy propagation optimization, just bail out here. If this becomes a problem
				// in the future, we can handle more cases.
				return false
			}
			if !expr.Negated {
				// Positive expressions containing variables cannot be trivially negated
				// because they become unsafe (e.g., "x = 1" negated is "not x = 1" making x
				// unsafe.) We check if the vars in the expr are already safe.
				vis := ast.NewVarVisitor().WithParams(ast.VarVisitorParams{
					SkipRefCallHead: true,
					SkipClosures:    true,
				})
				vis.Walk(expr)
				unsafe := vis.Vars().Diff(safe).Diff(ast.ReservedVars)
				if len(unsafe) > 0 {
					return false
				}
			}
		}
	}

	// NOTE(tsandall): this limit is arbitrary–it's only in place to prevent the
	// partial evaluation result from blowing up. In the future, we could make this
	// configurable or do something more clever.
	return size <= 16
}

type nestedCheckVisitor struct {
	vis   *ast.GenericVisitor
	found bool
}

func newNestedCheckVisitor() *nestedCheckVisitor {
	v := &nestedCheckVisitor{}
	v.vis = ast.NewGenericVisitor(v.visit)
	return v
}

func (v *nestedCheckVisitor) visit(x interface{}) bool {
	switch x.(type) {
	case ast.Ref, ast.Call:
		v.found = true
	}
	return v.found
}

func containsNestedRefOrCall(vis *nestedCheckVisitor, expr *ast.Expr) bool {

	if expr.IsEquality() {
		for _, term := range expr.Operands() {
			if containsNestedRefOrCallInTerm(vis, term) {
				return true
			}
		}
		return false
	}

	if expr.IsCall() {
		for _, term := range expr.Operands() {
			vis.vis.Walk(term)
			if vis.found {
				return true
			}
		}
		return false
	}

	return containsNestedRefOrCallInTerm(vis, expr.Terms.(*ast.Term))
}

func containsNestedRefOrCallInTerm(vis *nestedCheckVisitor, term *ast.Term) bool {
	switch v := term.Value.(type) {
	case ast.Ref:
		for i := 1; i < len(v); i++ {
			vis.vis.Walk(v[i])
			if vis.found {
				return true
			}
		}
		return false
	default:
		vis.vis.Walk(v)
		if vis.found {
			return true
		}
		return false
	}
}

func complementedCartesianProduct(queries []ast.Body, idx int, curr ast.Body, iter func(ast.Body) error) error {
	if idx == len(queries) {
		return iter(curr)
	}
	for _, expr := range queries[idx] {
		curr = append(curr, expr.Complement())
		if err := complementedCartesianProduct(queries, idx+1, curr, iter); err != nil {
			return err
		}
		curr = curr[:len(curr)-1]
	}
	return nil
}

func isInputRef(term *ast.Term) bool {
	if ref, ok := term.Value.(ast.Ref); ok {
		if ref.HasPrefix(ast.InputRootRef) {
			return true
		}
	}
	return false
}

func isDataRef(term *ast.Term) bool {
	if ref, ok := term.Value.(ast.Ref); ok {
		if ref.HasPrefix(ast.DefaultRootRef) {
			return true
		}
	}
	return false
}

func merge(a, b ast.Value) (ast.Value, bool) {
	aObj, ok1 := a.(ast.Object)
	bObj, ok2 := b.(ast.Object)

	if ok1 && ok2 {
		return mergeObjects(aObj, bObj)
	}

	// nothing to merge, a wins
	return a, true
}

// mergeObjects returns a new Object containing the non-overlapping keys of
// the objA and objB. If there are overlapping keys between objA and objB,
// the values of associated with the keys are merged. Only
// objects can be merged with other objects. If the values cannot be merged,
// objB value will be overwritten by objA value.
func mergeObjects(objA, objB ast.Object) (result ast.Object, ok bool) {
	result = ast.NewObject()
	stop := objA.Until(func(k, v *ast.Term) bool {
		if v2 := objB.Get(k); v2 == nil {
			result.Insert(k, v)
		} else {
			obj1, ok1 := v.Value.(ast.Object)
			obj2, ok2 := v2.Value.(ast.Object)

			if !ok1 || !ok2 {
				result.Insert(k, v)
				return false
			}
			obj3, ok := mergeObjects(obj1, obj2)
			if !ok {
				return true
			}
			result.Insert(k, ast.NewTerm(obj3))
		}
		return false
	})
	if stop {
		return nil, false
	}
	objB.Foreach(func(k, v *ast.Term) {
		if v2 := objA.Get(k); v2 == nil {
			result.Insert(k, v)
		}
	})
	return result, true
}

func refContainsNonScalar(ref ast.Ref) bool {
	for _, term := range ref[1:] {
		if !ast.IsScalar(term.Value) {
			return true
		}
	}
	return false
}

func suppressEarlyExit(err error) error {
	ee, ok := err.(*earlyExitError)
	if !ok {
		return err
	}
	return ee.prev // nil if we're done
}
