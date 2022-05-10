// Copyright 2021 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package errors contains reusable error-related code for the storage layer.
package errors

import (
	"fmt"

	"github.com/open-policy-agent/opa/storage"
)

const ArrayIndexTypeMsg = "array index must be integer"
const DoesNotExistMsg = "document does not exist"
const OutOfRangeMsg = "array index out of range"

func NewNotFoundError(path storage.Path) *storage.Error {
	return NewNotFoundErrorWithHint(path, DoesNotExistMsg)
}

func NewNotFoundErrorWithHint(path storage.Path, hint string) *storage.Error {
	return NewNotFoundErrorf("%v: %v", path.String(), hint)
}

func NewNotFoundErrorf(f string, a ...interface{}) *storage.Error {
	msg := fmt.Sprintf(f, a...)
	return &storage.Error{
		Code:    storage.NotFoundErr,
		Message: msg,
	}
}

func NewWriteConflictError(p storage.Path) *storage.Error {
	return &storage.Error{
		Code:    storage.WriteConflictErr,
		Message: p.String(),
	}
}
