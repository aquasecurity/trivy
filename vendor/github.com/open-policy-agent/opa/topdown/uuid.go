// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/internal/uuid"
)

type uuidCachingKey string

func builtinUUIDRFC4122(bctx BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {

	var key = uuidCachingKey(args[0].Value.String())

	val, ok := bctx.Cache.Get(key)
	if ok {
		return iter(val.(*ast.Term))
	}

	s, err := uuid.New(bctx.Seed)
	if err != nil {
		return err
	}

	result := ast.NewTerm(ast.String(s))
	bctx.Cache.Put(key, result)

	return iter(result)
}

func init() {
	RegisterBuiltinFunc(ast.UUIDRFC4122.Name, builtinUUIDRFC4122)
}
