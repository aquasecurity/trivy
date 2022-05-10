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
	idx, err := strconv.Atoi(s)
	if err != nil {
		return 0, errors.NewNotFoundErrorWithHint(path, errors.ArrayIndexTypeMsg)
	}
	if idx < 0 || idx >= len(arr) {
		return 0, errors.NewNotFoundErrorWithHint(path, errors.OutOfRangeMsg)
	}
	return idx, nil
}
