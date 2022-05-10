// Copyright 2021 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package future

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"
)

// ParserOptionsFromFutureImports transforms a slice of `ast.Import`s into the
// `ast.ParserOptions` that can be used to parse a statement according to the
// included "future.keywords" and "future.keywords.xyz" imports.
func ParserOptionsFromFutureImports(imports []*ast.Import) (ast.ParserOptions, error) {
	popts := ast.ParserOptions{
		FutureKeywords: []string{},
	}
	for _, imp := range imports {
		path := imp.Path.Value.(ast.Ref)
		if !ast.FutureRootDocument.Equal(path[0]) {
			continue
		}
		if len(path) >= 2 {
			if string(path[1].Value.(ast.String)) != "keywords" {
				return popts, fmt.Errorf("unknown future import: %v", imp)
			}
			if len(path) == 2 {
				// retun, one "future.keywords" import means we can disregard any others
				return ast.ParserOptions{AllFutureKeywords: true}, nil
			}
		}
		if len(path) == 3 {
			if imp.Alias != "" {
				return popts, fmt.Errorf("alias not supported")
			}
			popts.FutureKeywords = append(popts.FutureKeywords, string(path[2].Value.(ast.String)))
		}
	}
	return popts, nil
}
