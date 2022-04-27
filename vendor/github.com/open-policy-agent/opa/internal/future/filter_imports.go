// Copyright 2021 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package future

import "github.com/open-policy-agent/opa/ast"

// FilterFutureImports filters OUT any future imports from the passed slice of
// `*ast.Import`s.
func FilterFutureImports(imps []*ast.Import) []*ast.Import {
	ret := []*ast.Import{}
	for _, imp := range imps {
		path := imp.Path.Value.(ast.Ref)
		if !ast.FutureRootDocument.Equal(path[0]) {
			ret = append(ret, imp)
		}
	}
	return ret
}
