// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import "github.com/open-policy-agent/opa/metrics"

const (
	evalOpPlug                    = "eval_op_plug"
	evalOpResolve                 = "eval_op_resolve"
	evalOpRuleIndex               = "eval_op_rule_index"
	evalOpBuiltinCall             = "eval_op_builtin_call"
	evalOpVirtualCacheHit         = "eval_op_virtual_cache_hit"
	evalOpVirtualCacheMiss        = "eval_op_virtual_cache_miss"
	evalOpBaseCacheHit            = "eval_op_base_cache_hit"
	evalOpBaseCacheMiss           = "eval_op_base_cache_miss"
	evalOpComprehensionCacheSkip  = "eval_op_comprehension_cache_skip"
	evalOpComprehensionCacheBuild = "eval_op_comprehension_cache_build"
	evalOpComprehensionCacheHit   = "eval_op_comprehension_cache_hit"
	evalOpComprehensionCacheMiss  = "eval_op_comprehension_cache_miss"
	partialOpSaveUnify            = "partial_op_save_unify"
	partialOpSaveSetContains      = "partial_op_save_set_contains"
	partialOpSaveSetContainsRec   = "partial_op_save_set_contains_rec"
	partialOpCopyPropagation      = "partial_op_copy_propagation"
)

// Instrumentation implements helper functions to instrument query evaluation
// to diagnose performance issues. Instrumentation may be expensive in some
// cases, so it is disabled by default.
type Instrumentation struct {
	m metrics.Metrics
}

// NewInstrumentation returns a new Instrumentation object. Performance
// diagnostics recorded on this Instrumentation object will stored in m.
func NewInstrumentation(m metrics.Metrics) *Instrumentation {
	return &Instrumentation{
		m: m,
	}
}

func (instr *Instrumentation) startTimer(name string) {
	if instr == nil {
		return
	}
	instr.m.Timer(name).Start()
}

func (instr *Instrumentation) stopTimer(name string) {
	if instr == nil {
		return
	}
	delta := instr.m.Timer(name).Stop()
	instr.m.Histogram(name).Update(delta)
}

func (instr *Instrumentation) counterIncr(name string) {
	if instr == nil {
		return
	}
	instr.m.Counter(name).Incr()
}
