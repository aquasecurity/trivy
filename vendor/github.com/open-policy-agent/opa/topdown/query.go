package topdown

import (
	"context"
	"crypto/rand"
	"io"
	"sort"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/resolver"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/topdown/cache"
	"github.com/open-policy-agent/opa/topdown/copypropagation"
	"github.com/open-policy-agent/opa/topdown/print"
	"github.com/open-policy-agent/opa/tracing"
)

// QueryResultSet represents a collection of results returned by a query.
type QueryResultSet []QueryResult

// QueryResult represents a single result returned by a query. The result
// contains bindings for all variables that appear in the query.
type QueryResult map[ast.Var]*ast.Term

// Query provides a configurable interface for performing query evaluation.
type Query struct {
	seed                   io.Reader
	time                   time.Time
	cancel                 Cancel
	query                  ast.Body
	queryCompiler          ast.QueryCompiler
	compiler               *ast.Compiler
	store                  storage.Store
	txn                    storage.Transaction
	input                  *ast.Term
	external               *resolverTrie
	tracers                []QueryTracer
	plugTraceVars          bool
	unknowns               []*ast.Term
	partialNamespace       string
	skipSaveNamespace      bool
	metrics                metrics.Metrics
	instr                  *Instrumentation
	disableInlining        []ast.Ref
	shallowInlining        bool
	genvarprefix           string
	runtime                *ast.Term
	builtins               map[string]*Builtin
	indexing               bool
	earlyExit              bool
	interQueryBuiltinCache cache.InterQueryCache
	strictBuiltinErrors    bool
	printHook              print.Hook
	tracingOpts            tracing.Options
}

// Builtin represents a built-in function that queries can call.
type Builtin struct {
	Decl *ast.Builtin
	Func BuiltinFunc
}

// NewQuery returns a new Query object that can be run.
func NewQuery(query ast.Body) *Query {
	return &Query{
		query:        query,
		genvarprefix: ast.WildcardPrefix,
		indexing:     true,
		earlyExit:    true,
		external:     newResolverTrie(),
	}
}

// WithQueryCompiler sets the queryCompiler used for the query.
func (q *Query) WithQueryCompiler(queryCompiler ast.QueryCompiler) *Query {
	q.queryCompiler = queryCompiler
	return q
}

// WithCompiler sets the compiler to use for the query.
func (q *Query) WithCompiler(compiler *ast.Compiler) *Query {
	q.compiler = compiler
	return q
}

// WithStore sets the store to use for the query.
func (q *Query) WithStore(store storage.Store) *Query {
	q.store = store
	return q
}

// WithTransaction sets the transaction to use for the query. All queries
// should be performed over a consistent snapshot of the storage layer.
func (q *Query) WithTransaction(txn storage.Transaction) *Query {
	q.txn = txn
	return q
}

// WithCancel sets the cancellation object to use for the query. Set this if
// you need to abort queries based on a deadline. This is optional.
func (q *Query) WithCancel(cancel Cancel) *Query {
	q.cancel = cancel
	return q
}

// WithInput sets the input object to use for the query. References rooted at
// input will be evaluated against this value. This is optional.
func (q *Query) WithInput(input *ast.Term) *Query {
	q.input = input
	return q
}

// WithTracer adds a query tracer to use during evaluation. This is optional.
// Deprecated: Use WithQueryTracer instead.
func (q *Query) WithTracer(tracer Tracer) *Query {
	qt, ok := tracer.(QueryTracer)
	if !ok {
		qt = WrapLegacyTracer(tracer)
	}
	return q.WithQueryTracer(qt)
}

// WithQueryTracer adds a query tracer to use during evaluation. This is optional.
// Disabled QueryTracers will be ignored.
func (q *Query) WithQueryTracer(tracer QueryTracer) *Query {
	if !tracer.Enabled() {
		return q
	}

	q.tracers = append(q.tracers, tracer)

	// If *any* of the tracers require local variable metadata we need to
	// enabled plugging local trace variables.
	conf := tracer.Config()
	if conf.PlugLocalVars {
		q.plugTraceVars = true
	}

	return q
}

// WithMetrics sets the metrics collection to add evaluation metrics to. This
// is optional.
func (q *Query) WithMetrics(m metrics.Metrics) *Query {
	q.metrics = m
	return q
}

// WithInstrumentation sets the instrumentation configuration to enable on the
// evaluation process. By default, instrumentation is turned off.
func (q *Query) WithInstrumentation(instr *Instrumentation) *Query {
	q.instr = instr
	return q
}

// WithUnknowns sets the initial set of variables or references to treat as
// unknown during query evaluation. This is required for partial evaluation.
func (q *Query) WithUnknowns(terms []*ast.Term) *Query {
	q.unknowns = terms
	return q
}

// WithPartialNamespace sets the namespace to use for supporting rules
// generated as part of the partial evaluation process. The ns value must be a
// valid package path component.
func (q *Query) WithPartialNamespace(ns string) *Query {
	q.partialNamespace = ns
	return q
}

// WithSkipPartialNamespace disables namespacing of saved support rules that are generated
// from the original policy (rules which are completely synthetic are still namespaced.)
func (q *Query) WithSkipPartialNamespace(yes bool) *Query {
	q.skipSaveNamespace = yes
	return q
}

// WithDisableInlining adds a set of paths to the query that should be excluded from
// inlining. Inlining during partial evaluation can be expensive in some cases
// (e.g., when a cross-product is computed.) Disabling inlining avoids expensive
// computation at the cost of generating support rules.
func (q *Query) WithDisableInlining(paths []ast.Ref) *Query {
	q.disableInlining = paths
	return q
}

// WithShallowInlining disables aggressive inlining performed during partial evaluation.
// When shallow inlining is enabled rules that depend (transitively) on unknowns are not inlined.
// Only rules/values that are completely known will be inlined.
func (q *Query) WithShallowInlining(yes bool) *Query {
	q.shallowInlining = yes
	return q
}

// WithRuntime sets the runtime data to execute the query with. The runtime data
// can be returned by the `opa.runtime` built-in function.
func (q *Query) WithRuntime(runtime *ast.Term) *Query {
	q.runtime = runtime
	return q
}

// WithBuiltins adds a set of built-in functions that can be called by the
// query.
func (q *Query) WithBuiltins(builtins map[string]*Builtin) *Query {
	q.builtins = builtins
	return q
}

// WithIndexing will enable or disable using rule indexing for the evaluation
// of the query. The default is enabled.
func (q *Query) WithIndexing(enabled bool) *Query {
	q.indexing = enabled
	return q
}

// WithEarlyExit will enable or disable using 'early exit' for the evaluation
// of the query. The default is enabled.
func (q *Query) WithEarlyExit(enabled bool) *Query {
	q.earlyExit = enabled
	return q
}

// WithSeed sets a reader that will seed randomization required by built-in functions.
// If a seed is not provided crypto/rand.Reader is used.
func (q *Query) WithSeed(r io.Reader) *Query {
	q.seed = r
	return q
}

// WithTime sets the time that will be returned by the time.now_ns() built-in function.
func (q *Query) WithTime(x time.Time) *Query {
	q.time = x
	return q
}

// WithInterQueryBuiltinCache sets the inter-query cache that built-in functions can utilize.
func (q *Query) WithInterQueryBuiltinCache(c cache.InterQueryCache) *Query {
	q.interQueryBuiltinCache = c
	return q
}

// WithStrictBuiltinErrors tells the evaluator to treat all built-in function errors as fatal errors.
func (q *Query) WithStrictBuiltinErrors(yes bool) *Query {
	q.strictBuiltinErrors = yes
	return q
}

// WithResolver configures an external resolver to use for the given ref.
func (q *Query) WithResolver(ref ast.Ref, r resolver.Resolver) *Query {
	q.external.Put(ref, r)
	return q
}

func (q *Query) WithPrintHook(h print.Hook) *Query {
	q.printHook = h
	return q
}

// WithDistributedTracingOpts sets the options to be used by distributed tracing.
func (q *Query) WithDistributedTracingOpts(tr tracing.Options) *Query {
	q.tracingOpts = tr
	return q
}

// PartialRun executes partial evaluation on the query with respect to unknown
// values. Partial evaluation attempts to evaluate as much of the query as
// possible without requiring values for the unknowns set on the query. The
// result of partial evaluation is a new set of queries that can be evaluated
// once the unknown value is known. In addition to new queries, partial
// evaluation may produce additional support modules that should be used in
// conjunction with the partially evaluated queries.
func (q *Query) PartialRun(ctx context.Context) (partials []ast.Body, support []*ast.Module, err error) {
	if q.partialNamespace == "" {
		q.partialNamespace = "partial" // lazily initialize partial namespace
	}
	if q.seed == nil {
		q.seed = rand.Reader
	}
	if !q.time.IsZero() {
		q.time = time.Now()
	}
	if q.metrics == nil {
		q.metrics = metrics.New()
	}
	f := &queryIDFactory{}
	b := newBindings(0, q.instr)
	e := &eval{
		ctx:                    ctx,
		metrics:                q.metrics,
		seed:                   q.seed,
		time:                   ast.NumberTerm(int64ToJSONNumber(q.time.UnixNano())),
		cancel:                 q.cancel,
		query:                  q.query,
		queryCompiler:          q.queryCompiler,
		queryIDFact:            f,
		queryID:                f.Next(),
		bindings:               b,
		compiler:               q.compiler,
		store:                  q.store,
		baseCache:              newBaseCache(),
		targetStack:            newRefStack(),
		txn:                    q.txn,
		input:                  q.input,
		external:               q.external,
		tracers:                q.tracers,
		traceEnabled:           len(q.tracers) > 0,
		plugTraceVars:          q.plugTraceVars,
		instr:                  q.instr,
		builtins:               q.builtins,
		builtinCache:           builtins.Cache{},
		interQueryBuiltinCache: q.interQueryBuiltinCache,
		virtualCache:           newVirtualCache(),
		comprehensionCache:     newComprehensionCache(),
		saveSet:                newSaveSet(q.unknowns, b, q.instr),
		saveStack:              newSaveStack(),
		saveSupport:            newSaveSupport(),
		saveNamespace:          ast.StringTerm(q.partialNamespace),
		skipSaveNamespace:      q.skipSaveNamespace,
		inliningControl: &inliningControl{
			shallow: q.shallowInlining,
		},
		genvarprefix:  q.genvarprefix,
		runtime:       q.runtime,
		indexing:      q.indexing,
		earlyExit:     q.earlyExit,
		builtinErrors: &builtinErrors{},
		printHook:     q.printHook,
	}

	if len(q.disableInlining) > 0 {
		e.inliningControl.PushDisable(q.disableInlining, false)
	}

	e.caller = e
	q.metrics.Timer(metrics.RegoPartialEval).Start()
	defer q.metrics.Timer(metrics.RegoPartialEval).Stop()

	livevars := ast.NewVarSet()

	ast.WalkVars(q.query, func(x ast.Var) bool {
		if !x.IsGenerated() {
			livevars.Add(x)
		}
		return false
	})

	p := copypropagation.New(livevars).WithCompiler(q.compiler)

	err = e.Run(func(e *eval) error {

		// Build output from saved expressions.
		body := ast.NewBody()

		for _, elem := range e.saveStack.Stack[len(e.saveStack.Stack)-1] {
			body.Append(elem.Plug(e.bindings))
		}

		// Include bindings as exprs so that when caller evals the result, they
		// can obtain values for the vars in their query.
		bindingExprs := []*ast.Expr{}
		_ = e.bindings.Iter(e.bindings, func(a, b *ast.Term) error {
			bindingExprs = append(bindingExprs, ast.Equality.Expr(a, b))
			return nil
		}) // cannot return error

		// Sort binding expressions so that results are deterministic.
		sort.Slice(bindingExprs, func(i, j int) bool {
			return bindingExprs[i].Compare(bindingExprs[j]) < 0
		})

		for i := range bindingExprs {
			body.Append(bindingExprs[i])
		}

		// Skip this rule body if it fails to type-check.
		// Type-checking failure means the rule body will never succeed.
		if !e.compiler.PassesTypeCheck(body) {
			return nil
		}

		if !q.shallowInlining {
			body = applyCopyPropagation(p, e.instr, body)
		}

		partials = append(partials, body)
		return nil
	})

	support = e.saveSupport.List()

	if q.strictBuiltinErrors && len(e.builtinErrors.errs) > 0 {
		err = e.builtinErrors.errs[0]
	}

	for i := range support {
		sort.Slice(support[i].Rules, func(j, k int) bool {
			return support[i].Rules[j].Compare(support[i].Rules[k]) < 0
		})
	}

	return partials, support, err
}

// Run is a wrapper around Iter that accumulates query results and returns them
// in one shot.
func (q *Query) Run(ctx context.Context) (QueryResultSet, error) {
	qrs := QueryResultSet{}
	return qrs, q.Iter(ctx, func(qr QueryResult) error {
		qrs = append(qrs, qr)
		return nil
	})
}

// Iter executes the query and invokes the iter function with query results
// produced by evaluating the query.
func (q *Query) Iter(ctx context.Context, iter func(QueryResult) error) error {
	if q.seed == nil {
		q.seed = rand.Reader
	}
	if q.time.IsZero() {
		q.time = time.Now()
	}
	if q.metrics == nil {
		q.metrics = metrics.New()
	}
	f := &queryIDFactory{}
	e := &eval{
		ctx:                    ctx,
		metrics:                q.metrics,
		seed:                   q.seed,
		time:                   ast.NumberTerm(int64ToJSONNumber(q.time.UnixNano())),
		cancel:                 q.cancel,
		query:                  q.query,
		queryCompiler:          q.queryCompiler,
		queryIDFact:            f,
		queryID:                f.Next(),
		bindings:               newBindings(0, q.instr),
		compiler:               q.compiler,
		store:                  q.store,
		baseCache:              newBaseCache(),
		targetStack:            newRefStack(),
		txn:                    q.txn,
		input:                  q.input,
		external:               q.external,
		tracers:                q.tracers,
		traceEnabled:           len(q.tracers) > 0,
		plugTraceVars:          q.plugTraceVars,
		instr:                  q.instr,
		builtins:               q.builtins,
		builtinCache:           builtins.Cache{},
		interQueryBuiltinCache: q.interQueryBuiltinCache,
		virtualCache:           newVirtualCache(),
		comprehensionCache:     newComprehensionCache(),
		genvarprefix:           q.genvarprefix,
		runtime:                q.runtime,
		indexing:               q.indexing,
		earlyExit:              q.earlyExit,
		builtinErrors:          &builtinErrors{},
		printHook:              q.printHook,
		tracingOpts:            q.tracingOpts,
	}
	e.caller = e
	q.metrics.Timer(metrics.RegoQueryEval).Start()
	err := e.Run(func(e *eval) error {
		qr := QueryResult{}
		_ = e.bindings.Iter(nil, func(k, v *ast.Term) error {
			qr[k.Value.(ast.Var)] = v
			return nil
		}) // cannot return error
		return iter(qr)
	})

	if q.strictBuiltinErrors && err == nil && len(e.builtinErrors.errs) > 0 {
		err = e.builtinErrors.errs[0]
	}

	q.metrics.Timer(metrics.RegoQueryEval).Stop()
	return err
}
