// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package resolver

import (
	"context"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/metrics"
)

// Resolver defines an external value resolver for OPA evaluations.
type Resolver interface {
	Eval(context.Context, Input) (Result, error)
}

// Input as provided to a Resolver instance when evaluating.
type Input struct {
	Ref     ast.Ref
	Input   *ast.Term
	Metrics metrics.Metrics
}

// Result of resolving a ref.
type Result struct {
	Value ast.Value
}
