// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

import (
	"fmt"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/util"
)

// RuleIndex defines the interface for rule indices.
type RuleIndex interface {

	// Build tries to construct an index for the given rules. If the index was
	// constructed, it returns true, otherwise false.
	Build(rules []*Rule) bool

	// Lookup searches the index for rules that will match the provided
	// resolver. If the resolver returns an error, it is returned via err.
	Lookup(resolver ValueResolver) (*IndexResult, error)

	// AllRules traverses the index and returns all rules that will match
	// the provided resolver without any optimizations (effectively with
	// indexing disabled). If the resolver returns an error, it is returned
	// via err.
	AllRules(resolver ValueResolver) (*IndexResult, error)
}

// IndexResult contains the result of an index lookup.
type IndexResult struct {
	Kind      DocKind
	Rules     []*Rule
	Else      map[*Rule][]*Rule
	Default   *Rule
	EarlyExit bool
}

// NewIndexResult returns a new IndexResult object.
func NewIndexResult(kind DocKind) *IndexResult {
	return &IndexResult{
		Kind: kind,
		Else: map[*Rule][]*Rule{},
	}
}

// Empty returns true if there are no rules to evaluate.
func (ir *IndexResult) Empty() bool {
	return len(ir.Rules) == 0 && ir.Default == nil
}

type baseDocEqIndex struct {
	skipIndexing Set
	isVirtual    func(Ref) bool
	root         *trieNode
	defaultRule  *Rule
	kind         DocKind
}

func newBaseDocEqIndex(isVirtual func(Ref) bool) *baseDocEqIndex {
	return &baseDocEqIndex{
		skipIndexing: NewSet(NewTerm(InternalPrint.Ref())),
		isVirtual:    isVirtual,
		root:         newTrieNodeImpl(),
	}
}

func (i *baseDocEqIndex) Build(rules []*Rule) bool {
	if len(rules) == 0 {
		return false
	}

	i.kind = rules[0].Head.DocKind()
	indices := newrefindices(i.isVirtual)

	// build indices for each rule.
	for idx := range rules {
		WalkRules(rules[idx], func(rule *Rule) bool {
			if rule.Default {
				i.defaultRule = rule
				return false
			}
			var skip bool
			for _, expr := range rule.Body {
				if op := expr.OperatorTerm(); op != nil && i.skipIndexing.Contains(op) {
					skip = true
					break
				}
			}
			if !skip {
				for _, expr := range rule.Body {
					indices.Update(rule, expr)
				}
			}
			return false
		})
	}

	// build trie out of indices.
	for idx := range rules {
		var prio int
		WalkRules(rules[idx], func(rule *Rule) bool {
			if rule.Default {
				return false
			}
			node := i.root
			if indices.Indexed(rule) {
				for _, ref := range indices.Sorted() {
					node = node.Insert(ref, indices.Value(rule, ref), indices.Mapper(rule, ref))
				}
			}
			// Insert rule into trie with (insertion order, priority order)
			// tuple. Retaining the insertion order allows us to return rules
			// in the order they were passed to this function.
			node.append([...]int{idx, prio}, rule)
			prio++
			return false
		})
	}
	return true
}

func (i *baseDocEqIndex) Lookup(resolver ValueResolver) (*IndexResult, error) {

	tr := newTrieTraversalResult()

	err := i.root.Traverse(resolver, tr)
	if err != nil {
		return nil, err
	}

	result := NewIndexResult(i.kind)
	result.Default = i.defaultRule
	result.Rules = make([]*Rule, 0, len(tr.ordering))

	for _, pos := range tr.ordering {
		sort.Slice(tr.unordered[pos], func(i, j int) bool {
			return tr.unordered[pos][i].prio[1] < tr.unordered[pos][j].prio[1]
		})
		nodes := tr.unordered[pos]
		root := nodes[0].rule

		result.Rules = append(result.Rules, root)
		if len(nodes) > 1 {
			result.Else[root] = make([]*Rule, len(nodes)-1)
			for i := 1; i < len(nodes); i++ {
				result.Else[root][i-1] = nodes[i].rule
			}
		}
	}

	result.EarlyExit = tr.values.Len() == 1 && tr.values.Slice()[0].IsGround()

	return result, nil
}

func (i *baseDocEqIndex) AllRules(resolver ValueResolver) (*IndexResult, error) {
	tr := newTrieTraversalResult()

	// Walk over the rule trie and accumulate _all_ rules
	rw := &ruleWalker{result: tr}
	i.root.Do(rw)

	result := NewIndexResult(i.kind)
	result.Default = i.defaultRule
	result.Rules = make([]*Rule, 0, len(tr.ordering))

	for _, pos := range tr.ordering {
		sort.Slice(tr.unordered[pos], func(i, j int) bool {
			return tr.unordered[pos][i].prio[1] < tr.unordered[pos][j].prio[1]
		})
		nodes := tr.unordered[pos]
		root := nodes[0].rule
		result.Rules = append(result.Rules, root)
		if len(nodes) > 1 {
			result.Else[root] = make([]*Rule, len(nodes)-1)
			for i := 1; i < len(nodes); i++ {
				result.Else[root][i-1] = nodes[i].rule
			}
		}
	}

	result.EarlyExit = tr.values.Len() == 1 && tr.values.Slice()[0].IsGround()

	return result, nil
}

type ruleWalker struct {
	result *trieTraversalResult
}

func (r *ruleWalker) Do(x interface{}) trieWalker {
	tn := x.(*trieNode)
	r.result.Add(tn)
	return r
}

type valueMapper struct {
	Key      string
	MapValue func(Value) Value
}

type refindex struct {
	Ref    Ref
	Value  Value
	Mapper *valueMapper
}

type refindices struct {
	isVirtual func(Ref) bool
	rules     map[*Rule][]*refindex
	frequency *util.HashMap
	sorted    []Ref
}

func newrefindices(isVirtual func(Ref) bool) *refindices {
	return &refindices{
		isVirtual: isVirtual,
		rules:     map[*Rule][]*refindex{},
		frequency: util.NewHashMap(func(a, b util.T) bool {
			r1, r2 := a.(Ref), b.(Ref)
			return r1.Equal(r2)
		}, func(x util.T) int {
			return x.(Ref).Hash()
		}),
	}
}

// Update attempts to update the refindices for the given expression in the
// given rule. If the expression cannot be indexed the update does not affect
// the indices.
func (i *refindices) Update(rule *Rule, expr *Expr) {

	if expr.Negated {
		return
	}

	if len(expr.With) > 0 {
		// NOTE(tsandall): In the future, we may need to consider expressions
		// that have with statements applied to them.
		return
	}

	op := expr.Operator()

	if op.Equal(Equality.Ref()) {
		i.updateEq(rule, expr)
	} else if op.Equal(Equal.Ref()) && len(expr.Operands()) == 2 {
		// NOTE(tsandall): if equal() is called with more than two arguments the
		// output value is being captured in which case the indexer cannot
		// exclude the rule if the equal() call would return false (because the
		// false value must still be produced.)
		i.updateEq(rule, expr)
	} else if op.Equal(GlobMatch.Ref()) {
		i.updateGlobMatch(rule, expr)
	}
}

// Sorted returns a sorted list of references that the indices were built from.
// References that appear more frequently in the indexed rules are ordered
// before less frequently appearing references.
func (i *refindices) Sorted() []Ref {

	if i.sorted == nil {
		counts := make([]int, 0, i.frequency.Len())
		i.sorted = make([]Ref, 0, i.frequency.Len())

		i.frequency.Iter(func(k, v util.T) bool {
			counts = append(counts, v.(int))
			i.sorted = append(i.sorted, k.(Ref))
			return false
		})

		sort.Slice(i.sorted, func(a, b int) bool {
			if counts[a] > counts[b] {
				return true
			} else if counts[b] > counts[a] {
				return false
			}
			return i.sorted[a][0].Loc().Compare(i.sorted[b][0].Loc()) < 0
		})
	}

	return i.sorted
}

func (i *refindices) Indexed(rule *Rule) bool {
	return len(i.rules[rule]) > 0
}

func (i *refindices) Value(rule *Rule, ref Ref) Value {
	if index := i.index(rule, ref); index != nil {
		return index.Value
	}
	return nil
}

func (i *refindices) Mapper(rule *Rule, ref Ref) *valueMapper {
	if index := i.index(rule, ref); index != nil {
		return index.Mapper
	}
	return nil
}

func (i *refindices) updateEq(rule *Rule, expr *Expr) {
	a, b := expr.Operand(0), expr.Operand(1)
	args := rule.Head.Args
	if idx, ok := eqOperandsToRefAndValue(i.isVirtual, args, a, b); ok {
		i.insert(rule, idx)
		return
	}
	if idx, ok := eqOperandsToRefAndValue(i.isVirtual, args, b, a); ok {
		i.insert(rule, idx)
		return
	}
}

func (i *refindices) updateGlobMatch(rule *Rule, expr *Expr) {
	args := rule.Head.Args

	delim, ok := globDelimiterToString(expr.Operand(1))
	if !ok {
		return
	}

	if arr := globPatternToArray(expr.Operand(0), delim); arr != nil {
		// The 3rd operand of glob.match is the value to match. We assume the
		// 3rd operand was a reference that has been rewritten and bound to a
		// variable earlier in the query OR a function argument variable.
		match := expr.Operand(2)
		if _, ok := match.Value.(Var); ok {
			var ref Ref
			for _, other := range i.rules[rule] {
				if _, ok := other.Value.(Var); ok && other.Value.Compare(match.Value) == 0 {
					ref = other.Ref
				}
			}
			if ref == nil {
				for j, arg := range args {
					if arg.Equal(match) {
						ref = Ref{FunctionArgRootDocument, IntNumberTerm(j)}
					}
				}
			}
			if ref != nil {
				i.insert(rule, &refindex{
					Ref:   ref,
					Value: arr.Value,
					Mapper: &valueMapper{
						Key: delim,
						MapValue: func(v Value) Value {
							if s, ok := v.(String); ok {
								return stringSliceToArray(splitStringEscaped(string(s), delim))
							}
							return v
						},
					},
				})
			}
		}
	}
}

func (i *refindices) insert(rule *Rule, index *refindex) {

	count, ok := i.frequency.Get(index.Ref)
	if !ok {
		count = 0
	}

	i.frequency.Put(index.Ref, count.(int)+1)

	for pos, other := range i.rules[rule] {
		if other.Ref.Equal(index.Ref) {
			i.rules[rule][pos] = index
			return
		}
	}

	i.rules[rule] = append(i.rules[rule], index)
}

func (i *refindices) index(rule *Rule, ref Ref) *refindex {
	for _, index := range i.rules[rule] {
		if index.Ref.Equal(ref) {
			return index
		}
	}
	return nil
}

type trieWalker interface {
	Do(x interface{}) trieWalker
}

type trieTraversalResult struct {
	unordered map[int][]*ruleNode
	ordering  []int
	values    Set
}

func newTrieTraversalResult() *trieTraversalResult {
	return &trieTraversalResult{
		unordered: map[int][]*ruleNode{},
		values:    NewSet(),
	}
}

func (tr *trieTraversalResult) Add(t *trieNode) {
	for _, node := range t.rules {
		root := node.prio[0]
		nodes, ok := tr.unordered[root]
		if !ok {
			tr.ordering = append(tr.ordering, root)
		}
		tr.unordered[root] = append(nodes, node)
	}
	if t.values != nil {
		t.values.Foreach(func(v *Term) { tr.values.Add(v) })
	}
}

type trieNode struct {
	ref       Ref
	values    Set
	mappers   []*valueMapper
	next      *trieNode
	any       *trieNode
	undefined *trieNode
	scalars   map[Value]*trieNode
	array     *trieNode
	rules     []*ruleNode
}

func (node *trieNode) String() string {
	var flags []string
	flags = append(flags, fmt.Sprintf("self:%p", node))
	if len(node.ref) > 0 {
		flags = append(flags, node.ref.String())
	}
	if node.next != nil {
		flags = append(flags, fmt.Sprintf("next:%p", node.next))
	}
	if node.any != nil {
		flags = append(flags, fmt.Sprintf("any:%p", node.any))
	}
	if node.undefined != nil {
		flags = append(flags, fmt.Sprintf("undefined:%p", node.undefined))
	}
	if node.array != nil {
		flags = append(flags, fmt.Sprintf("array:%p", node.array))
	}
	if len(node.scalars) > 0 {
		buf := make([]string, 0, len(node.scalars))
		for k, v := range node.scalars {
			buf = append(buf, fmt.Sprintf("scalar(%v):%p", k, v))
		}
		sort.Strings(buf)
		flags = append(flags, strings.Join(buf, " "))
	}
	if len(node.rules) > 0 {
		flags = append(flags, fmt.Sprintf("%d rule(s)", len(node.rules)))
	}
	if len(node.mappers) > 0 {
		flags = append(flags, fmt.Sprintf("%d mapper(s)", len(node.mappers)))
	}
	if l := node.values.Len(); l > 0 {
		flags = append(flags, fmt.Sprintf("%d value(s)", l))
	}
	return strings.Join(flags, " ")
}

func (node *trieNode) append(prio [2]int, rule *Rule) {
	node.rules = append(node.rules, &ruleNode{prio, rule})

	if node.values != nil {
		node.values.Add(rule.Head.Value)
		return
	}

	if node.values == nil && rule.Head.DocKind() == CompleteDoc {
		node.values = NewSet(rule.Head.Value)
	}
}

type ruleNode struct {
	prio [2]int
	rule *Rule
}

func newTrieNodeImpl() *trieNode {
	return &trieNode{
		scalars: map[Value]*trieNode{},
	}
}

func (node *trieNode) Do(walker trieWalker) {
	next := walker.Do(node)
	if next == nil {
		return
	}
	if node.any != nil {
		node.any.Do(next)
	}
	if node.undefined != nil {
		node.undefined.Do(next)
	}
	for _, child := range node.scalars {
		child.Do(next)
	}
	if node.array != nil {
		node.array.Do(next)
	}
	if node.next != nil {
		node.next.Do(next)
	}
}

func (node *trieNode) Insert(ref Ref, value Value, mapper *valueMapper) *trieNode {

	if node.next == nil {
		node.next = newTrieNodeImpl()
		node.next.ref = ref
	}

	if mapper != nil {
		node.next.addMapper(mapper)
	}

	return node.next.insertValue(value)
}

func (node *trieNode) Traverse(resolver ValueResolver, tr *trieTraversalResult) error {

	if node == nil {
		return nil
	}

	tr.Add(node)

	return node.next.traverse(resolver, tr)
}

func (node *trieNode) addMapper(mapper *valueMapper) {
	for i := range node.mappers {
		if node.mappers[i].Key == mapper.Key {
			return
		}
	}
	node.mappers = append(node.mappers, mapper)
}

func (node *trieNode) insertValue(value Value) *trieNode {

	switch value := value.(type) {
	case nil:
		if node.undefined == nil {
			node.undefined = newTrieNodeImpl()
		}
		return node.undefined
	case Var:
		if node.any == nil {
			node.any = newTrieNodeImpl()
		}
		return node.any
	case Null, Boolean, Number, String:
		child, ok := node.scalars[value]
		if !ok {
			child = newTrieNodeImpl()
			node.scalars[value] = child
		}
		return child
	case *Array:
		if node.array == nil {
			node.array = newTrieNodeImpl()
		}
		return node.array.insertArray(value)
	}

	panic("illegal value")
}

func (node *trieNode) insertArray(arr *Array) *trieNode {

	if arr.Len() == 0 {
		return node
	}

	switch head := arr.Elem(0).Value.(type) {
	case Var:
		if node.any == nil {
			node.any = newTrieNodeImpl()
		}
		return node.any.insertArray(arr.Slice(1, -1))
	case Null, Boolean, Number, String:
		child, ok := node.scalars[head]
		if !ok {
			child = newTrieNodeImpl()
			node.scalars[head] = child
		}
		return child.insertArray(arr.Slice(1, -1))
	}

	panic("illegal value")
}

func (node *trieNode) traverse(resolver ValueResolver, tr *trieTraversalResult) error {

	if node == nil {
		return nil
	}

	v, err := resolver.Resolve(node.ref)
	if err != nil {
		if IsUnknownValueErr(err) {
			return node.traverseUnknown(resolver, tr)
		}
		return err
	}

	if node.undefined != nil {
		err = node.undefined.Traverse(resolver, tr)
		if err != nil {
			return err
		}
	}

	if v == nil {
		return nil
	}

	if node.any != nil {
		err = node.any.Traverse(resolver, tr)
		if err != nil {
			return err
		}
	}

	if err := node.traverseValue(resolver, tr, v); err != nil {
		return err
	}

	for i := range node.mappers {
		if err := node.traverseValue(resolver, tr, node.mappers[i].MapValue(v)); err != nil {
			return err
		}
	}

	return nil
}

func (node *trieNode) traverseValue(resolver ValueResolver, tr *trieTraversalResult, value Value) error {

	switch value := value.(type) {
	case *Array:
		if node.array == nil {
			return nil
		}
		return node.array.traverseArray(resolver, tr, value)

	case Null, Boolean, Number, String:
		child, ok := node.scalars[value]
		if !ok {
			return nil
		}
		return child.Traverse(resolver, tr)
	}

	return nil
}

func (node *trieNode) traverseArray(resolver ValueResolver, tr *trieTraversalResult, arr *Array) error {

	if arr.Len() == 0 {
		return node.Traverse(resolver, tr)
	}

	head := arr.Elem(0).Value

	if !IsScalar(head) {
		return nil
	}

	if node.any != nil {
		err := node.any.traverseArray(resolver, tr, arr.Slice(1, -1))
		if err != nil {
			return err
		}
	}

	child, ok := node.scalars[head]
	if !ok {
		return nil
	}

	return child.traverseArray(resolver, tr, arr.Slice(1, -1))
}

func (node *trieNode) traverseUnknown(resolver ValueResolver, tr *trieTraversalResult) error {

	if node == nil {
		return nil
	}

	if err := node.Traverse(resolver, tr); err != nil {
		return err
	}

	if err := node.undefined.traverseUnknown(resolver, tr); err != nil {
		return err
	}

	if err := node.any.traverseUnknown(resolver, tr); err != nil {
		return err
	}

	if err := node.array.traverseUnknown(resolver, tr); err != nil {
		return err
	}

	for _, child := range node.scalars {
		if err := child.traverseUnknown(resolver, tr); err != nil {
			return err
		}
	}

	return nil
}

// If term `a` is one of the function's operands, we store a Ref: `args[0]`
// for the argument number. So for `f(x, y) { x = 10; y = 12 }`, we'll
// bind `args[0]` and `args[1]` to this rule when called for (x=10) and
// (y=12) respectively.
func eqOperandsToRefAndValue(isVirtual func(Ref) bool, args []*Term, a, b *Term) (*refindex, bool) {
	switch v := a.Value.(type) {
	case Var:
		for i, arg := range args {
			if arg.Value.Compare(v) == 0 {
				if bval, ok := indexValue(b); ok {
					return &refindex{Ref: Ref{FunctionArgRootDocument, IntNumberTerm(i)}, Value: bval}, true
				}
			}
		}
	case Ref:
		if !RootDocumentNames.Contains(v[0]) {
			return nil, false
		}
		if isVirtual(v) {
			return nil, false
		}
		if v.IsNested() || !v.IsGround() {
			return nil, false
		}
		if bval, ok := indexValue(b); ok {
			return &refindex{Ref: v, Value: bval}, true
		}
	}
	return nil, false
}

func indexValue(b *Term) (Value, bool) {
	switch b := b.Value.(type) {
	case Null, Boolean, Number, String, Var:
		return b, true
	case *Array:
		stop := false
		first := true
		vis := NewGenericVisitor(func(x interface{}) bool {
			if first {
				first = false
				return false
			}
			switch x.(type) {
			// No nested structures or values that require evaluation (other than var).
			case *Array, Object, Set, *ArrayComprehension, *ObjectComprehension, *SetComprehension, Ref:
				stop = true
			}
			return stop
		})
		vis.Walk(b)
		if !stop {
			return b, true
		}
	}

	return nil, false
}

func globDelimiterToString(delim *Term) (string, bool) {

	arr, ok := delim.Value.(*Array)
	if !ok {
		return "", false
	}

	var result string

	if arr.Len() == 0 {
		result = "."
	} else {
		for i := 0; i < arr.Len(); i++ {
			term := arr.Elem(i)
			s, ok := term.Value.(String)
			if !ok {
				return "", false
			}
			result += string(s)
		}
	}

	return result, true
}

func globPatternToArray(pattern *Term, delim string) *Term {

	s, ok := pattern.Value.(String)
	if !ok {
		return nil
	}

	parts := splitStringEscaped(string(s), delim)
	arr := make([]*Term, len(parts))

	for i := range parts {
		if parts[i] == "*" {
			arr[i] = VarTerm("$globwildcard")
		} else {
			var escaped bool
			for _, c := range parts[i] {
				if c == '\\' {
					escaped = !escaped
					continue
				}
				if !escaped {
					switch c {
					case '[', '?', '{', '*':
						// TODO(tsandall): super glob and character pattern
						// matching not supported yet.
						return nil
					}
				}
				escaped = false
			}
			arr[i] = StringTerm(parts[i])
		}
	}

	return NewTerm(NewArray(arr...))
}

// splits s on characters in delim except if delim characters have been escaped
// with reverse solidus.
func splitStringEscaped(s string, delim string) []string {

	var last, curr int
	var escaped bool
	var result []string

	for ; curr < len(s); curr++ {
		if s[curr] == '\\' || escaped {
			escaped = !escaped
			continue
		}
		if strings.ContainsRune(delim, rune(s[curr])) {
			result = append(result, s[last:curr])
			last = curr + 1
		}
	}

	result = append(result, s[last:])

	return result
}

func stringSliceToArray(s []string) *Array {
	arr := make([]*Term, len(s))
	for i, v := range s {
		arr[i] = StringTerm(v)
	}
	return NewArray(arr...)
}
