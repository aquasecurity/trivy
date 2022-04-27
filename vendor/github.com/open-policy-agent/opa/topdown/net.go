// Copyright 2021 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"net"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

type lookupIPAddrCacheKey string

// resolv is the same as net.DefaultResolver -- this is for mocking it out in tests
var resolv = &net.Resolver{}

func builtinLookupIPAddr(bctx BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
	a, err := builtins.StringOperand(operands[0].Value, 1)
	if err != nil {
		return err
	}
	name := string(a)

	err = verifyHost(bctx, name)
	if err != nil {
		return err
	}

	key := lookupIPAddrCacheKey(name)
	if val, ok := bctx.Cache.Get(key); ok {
		return iter(val.(*ast.Term))
	}

	addrs, err := resolv.LookupIPAddr(bctx.Context, name)
	if err != nil {
		// NOTE(sr): We can't do better than this right now, see https://github.com/golang/go/issues/36208
		if strings.Contains(err.Error(), "operation was canceled") || strings.Contains(err.Error(), "i/o timeout") {
			return Halt{
				Err: &Error{
					Code:     CancelErr,
					Message:  ast.NetLookupIPAddr.Name + ": " + err.Error(),
					Location: bctx.Location,
				},
			}
		}
		return err
	}

	ret := ast.NewSet()
	for _, a := range addrs {
		ret.Add(ast.StringTerm(a.String()))

	}
	t := ast.NewTerm(ret)
	bctx.Cache.Put(key, t)
	return iter(t)
}

func init() {
	RegisterBuiltinFunc(ast.NetLookupIPAddr.Name, builtinLookupIPAddr)
}
