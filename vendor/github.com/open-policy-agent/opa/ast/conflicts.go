// Copyright 2019 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

import (
	"strings"
)

// CheckPathConflicts returns a set of errors indicating paths that
// are in conflict with the result of the provided callable.
func CheckPathConflicts(c *Compiler, exists func([]string) (bool, error)) Errors {
	var errs Errors

	root := c.RuleTree.Child(DefaultRootDocument.Value)
	if root == nil {
		return nil
	}

	for _, node := range root.Children {
		errs = append(errs, checkDocumentConflicts(node, exists, nil)...)
	}

	return errs
}

func checkDocumentConflicts(node *TreeNode, exists func([]string) (bool, error), path []string) Errors {

	path = append(path, string(node.Key.(String)))

	if len(node.Values) > 0 {
		s := strings.Join(path, "/")
		if ok, err := exists(path); err != nil {
			return Errors{NewError(CompileErr, node.Values[0].(*Rule).Loc(), "conflict check for data path %v: %v", s, err.Error())}
		} else if ok {
			return Errors{NewError(CompileErr, node.Values[0].(*Rule).Loc(), "conflicting rule for data path %v found", s)}
		}
	}

	var errs Errors

	for _, child := range node.Children {
		errs = append(errs, checkDocumentConflicts(child, exists, path)...)
	}

	return errs
}
