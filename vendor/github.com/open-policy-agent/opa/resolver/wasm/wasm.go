// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package wasm

import (
	"context"
	"fmt"
	"strconv"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/internal/rego/opa"
	"github.com/open-policy-agent/opa/resolver"
)

// New creates a new Resolver instance which is using the Wasm module
// policy for the given entrypoint ref.
func New(entrypoints []ast.Ref, policy []byte, data interface{}) (*Resolver, error) {
	e, err := opa.LookupEngine("wasm")
	if err != nil {
		return nil, err
	}
	o, err := e.New().
		WithPolicyBytes(policy).
		WithDataJSON(data).
		Init()
	if err != nil {
		return nil, err
	}

	// Construct a quick lookup table of ref -> entrypoint ID
	// for handling evaluations. Only the entrypoints provided
	// by the caller will be constructed, this may be a subset
	// of entrypoints available in the Wasm module, however
	// only the configured ones will be used when Eval() is
	// called.
	entrypointRefToID := ast.NewValueMap()
	epIDs, err := o.Entrypoints(context.Background())
	if err != nil {
		return nil, err
	}
	for path, id := range epIDs {
		for _, ref := range entrypoints {
			refPtr, err := ref.Ptr()
			if err != nil {
				return nil, err
			}
			if refPtr == path {
				entrypointRefToID.Put(ref, ast.Number(strconv.Itoa(int(id))))
			}
		}
	}

	return &Resolver{
		entrypoints:   entrypoints,
		entrypointIDs: entrypointRefToID,
		o:             o,
	}, nil
}

// Resolver implements the resolver.Resolver interface
// using Wasm modules to perform an evaluation.
type Resolver struct {
	entrypoints   []ast.Ref
	entrypointIDs *ast.ValueMap
	o             opa.EvalEngine
}

// Entrypoints returns a list of entrypoints this resolver is configured to
// perform evaluations on.
func (r *Resolver) Entrypoints() []ast.Ref {
	return r.entrypoints
}

// Close shuts down the resolver.
func (r *Resolver) Close() {
	r.o.Close()
}

// Eval performs an evaluation using the provided input and the Wasm module
// associated with this Resolver instance.
func (r *Resolver) Eval(ctx context.Context, input resolver.Input) (resolver.Result, error) {
	v := r.entrypointIDs.Get(input.Ref)
	if v == nil {
		return resolver.Result{}, fmt.Errorf("unknown entrypoint %s", input.Ref)
	}

	numValue, ok := v.(ast.Number)
	if !ok {
		return resolver.Result{}, fmt.Errorf("internal error: invalid entrypoint id %s", numValue)
	}

	epID, ok := numValue.Int()
	if !ok {
		return resolver.Result{}, fmt.Errorf("internal error: invalid entrypoint id %s", numValue)
	}

	var in *interface{}
	if input.Input != nil {
		var str interface{} = []byte(input.Input.String())
		in = &str
	}

	opts := opa.EvalOpts{
		Input:      in,
		Entrypoint: int32(epID),
		Metrics:    input.Metrics,
	}
	out, err := r.o.Eval(ctx, opts)
	if err != nil {
		return resolver.Result{}, err
	}

	result, err := getResult(out)
	if err != nil {
		return resolver.Result{}, err
	}

	return resolver.Result{Value: result}, nil
}

// SetData will update the external data for the Wasm instance.
func (r *Resolver) SetData(ctx context.Context, data interface{}) error {
	return r.o.SetData(ctx, data)
}

// SetDataPath will set the provided data on the wasm instance at the specified path.
func (r *Resolver) SetDataPath(ctx context.Context, path []string, data interface{}) error {
	return r.o.SetDataPath(ctx, path, data)
}

// RemoveDataPath will remove any data at the specified path.
func (r *Resolver) RemoveDataPath(ctx context.Context, path []string) error {
	return r.o.RemoveDataPath(ctx, path)
}

func getResult(evalResult *opa.Result) (ast.Value, error) {

	parsed, err := ast.ParseTerm(string(evalResult.Result))
	if err != nil {
		return nil, fmt.Errorf("failed to parse wasm result: %s", err)
	}

	resultSet, ok := parsed.Value.(ast.Set)
	if !ok {
		return nil, fmt.Errorf("illegal result type")
	}

	if resultSet.Len() == 0 {
		return nil, nil
	}

	if resultSet.Len() > 1 {
		return nil, fmt.Errorf("illegal result type")
	}

	var obj ast.Object
	err = resultSet.Iter(func(term *ast.Term) error {
		obj, ok = term.Value.(ast.Object)
		if !ok || obj.Len() != 1 {
			return fmt.Errorf("illegal result type")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	result := obj.Get(ast.StringTerm("result"))

	return result.Value, nil
}
