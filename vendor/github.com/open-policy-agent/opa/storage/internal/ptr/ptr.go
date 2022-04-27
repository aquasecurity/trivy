// Copyright 2021 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package ptr provides utilities for pointer operations using storage layer paths.
package ptr

import (
	"strconv"

	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/internal/errors"
)

func Ptr(data interface{}, path storage.Path) (interface{}, error) {
	node := data
	for i := range path {
		key := path[i]
		switch curr := node.(type) {
		case map[string]interface{}:
			var ok bool
			if node, ok = curr[key]; !ok {
				return nil, errors.NewNotFoundError(path)
			}
		case []interface{}:
			pos, err := ValidateArrayIndex(curr, key, path)
			if err != nil {
				return nil, err
			}
			node = curr[pos]
		default:
			return nil, errors.NewNotFoundError(path)
		}
	}

	return node, nil
}

func ValidateArrayIndex(arr []interface{}, s string, path storage.Path) (int, error) {
	idx, ok := isInt(s)
	if !ok {
		return 0, errors.NewNotFoundErrorWithHint(path, errors.ArrayIndexTypeMsg)
	}
	return inRange(idx, arr, path)
}

// ValidateArrayIndexForWrite also checks that `s` is a valid way to address an
// array element like `ValidateArrayIndex`, but returns a `resource_conflict` error
// if it is not.
func ValidateArrayIndexForWrite(arr []interface{}, s string, i int, path storage.Path) (int, error) {
	idx, ok := isInt(s)
	if !ok {
		return 0, errors.NewWriteConflictError(path[:i-1])
	}
	return inRange(idx, arr, path)
}

func isInt(s string) (int, bool) {
	idx, err := strconv.Atoi(s)
	return idx, err == nil
}

func inRange(i int, arr []interface{}, path storage.Path) (int, error) {
	if i < 0 || i >= len(arr) {
		return 0, errors.NewNotFoundErrorWithHint(path, errors.OutOfRangeMsg)
	}
	return i, nil
}
