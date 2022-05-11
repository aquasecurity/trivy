// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"
)

var errBadPath = fmt.Errorf("bad document path")

func mergeTermWithValues(exist *ast.Term, pairs [][2]*ast.Term) (*ast.Term, error) {

	var result *ast.Term
	var init bool

	for i, pair := range pairs {

		if err := ast.IsValidImportPath(pair[0].Value); err != nil {
			return nil, errBadPath
		}

		target := pair[0].Value.(ast.Ref)

		// Copy the value if subsequent pairs in the slice would modify it.
		for j := i + 1; j < len(pairs); j++ {
			other := pairs[j][0].Value.(ast.Ref)
			if len(other) > len(target) && other.HasPrefix(target) {
				pair[1] = pair[1].Copy()
				break
			}
		}

		if len(target) == 1 {
			result = pair[1]
			init = true
		} else {
			if !init {
				result = exist.Copy()
				init = true
			}
			if result == nil {
				result = ast.NewTerm(makeTree(target[1:], pair[1]))
			} else {
				node := result
				done := false
				for i := 1; i < len(target)-1 && !done; i++ {
					obj, ok := node.Value.(ast.Object)
					if !ok {
						result = ast.NewTerm(makeTree(target[i:], pair[1]))
						done = true
						continue
					}
					if child := obj.Get(target[i]); !isObject(child) {
						obj.Insert(target[i], ast.NewTerm(makeTree(target[i+1:], pair[1])))
						done = true
					} else { // child is object
						node = child
					}
				}
				if !done {
					if obj, ok := node.Value.(ast.Object); ok {
						obj.Insert(target[len(target)-1], pair[1])
					} else {
						result = ast.NewTerm(makeTree(target[len(target)-1:], pair[1]))
					}
				}
			}
		}
	}

	if !init {
		result = exist
	}

	return result, nil
}

// makeTree returns an object that represents a document where the value v is
// the leaf and elements in k represent intermediate objects.
func makeTree(k ast.Ref, v *ast.Term) ast.Object {
	var obj ast.Object
	for i := len(k) - 1; i >= 1; i-- {
		obj = ast.NewObject(ast.Item(k[i], v))
		v = &ast.Term{Value: obj}
	}
	obj = ast.NewObject(ast.Item(k[0], v))
	return obj
}

func isObject(x *ast.Term) bool {
	if x == nil {
		return false
	}
	_, ok := x.Value.(ast.Object)
	return ok
}
