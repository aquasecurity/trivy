// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
)

// Halt is a special error type that built-in function implementations return to indicate
// that policy evaluation should stop immediately.
type Halt struct {
	Err error
}

func (h Halt) Error() string {
	return h.Err.Error()
}

func (h Halt) Unwrap() error { return h.Err }

// Error is the error type returned by the Eval and Query functions when
// an evaluation error occurs.
type Error struct {
	Code     string        `json:"code"`
	Message  string        `json:"message"`
	Location *ast.Location `json:"location,omitempty"`
}

const (

	// InternalErr represents an unknown evaluation error.
	InternalErr string = "eval_internal_error"

	// CancelErr indicates the evaluation process was cancelled.
	CancelErr string = "eval_cancel_error"

	// ConflictErr indicates a conflict was encountered during evaluation. For
	// instance, a conflict occurs if a rule produces multiple, differing values
	// for the same key in an object. Conflict errors indicate the policy does
	// not account for the data loaded into the policy engine.
	ConflictErr string = "eval_conflict_error"

	// TypeErr indicates evaluation stopped because an expression was applied to
	// a value of an inappropriate type.
	TypeErr string = "eval_type_error"

	// BuiltinErr indicates a built-in function received a semantically invalid
	// input or encountered some kind of runtime error, e.g., connection
	// timeout, connection refused, etc.
	BuiltinErr string = "eval_builtin_error"

	// WithMergeErr indicates that the real and replacement data could not be merged.
	WithMergeErr string = "eval_with_merge_error"
)

// IsError returns true if the err is an Error.
func IsError(err error) bool {
	var e *Error
	return errors.As(err, &e)
}

// IsCancel returns true if err was caused by cancellation.
func IsCancel(err error) bool {
	return errors.Is(err, &Error{Code: CancelErr})
}

// Is allows matching topdown errors using errors.Is (see IsCancel).
func (e *Error) Is(target error) bool {
	var t *Error
	if errors.As(target, &t) {
		return (t.Code == "" || e.Code == t.Code) &&
			(t.Message == "" || e.Message == t.Message) &&
			(t.Location == nil || t.Location.Compare(e.Location) == 0)
	}
	return false
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("%v: %v", e.Code, e.Message)

	if e.Location != nil {
		msg = e.Location.String() + ": " + msg
	}

	return msg
}

func functionConflictErr(loc *ast.Location) error {
	return &Error{
		Code:     ConflictErr,
		Location: loc,
		Message:  "functions must not produce multiple outputs for same inputs",
	}
}

func completeDocConflictErr(loc *ast.Location) error {
	return &Error{
		Code:     ConflictErr,
		Location: loc,
		Message:  "complete rules must not produce multiple outputs",
	}
}

func objectDocKeyConflictErr(loc *ast.Location) error {
	return &Error{
		Code:     ConflictErr,
		Location: loc,
		Message:  "object keys must be unique",
	}
}

func unsupportedBuiltinErr(loc *ast.Location) error {
	return &Error{
		Code:     InternalErr,
		Location: loc,
		Message:  "unsupported built-in",
	}
}

func mergeConflictErr(loc *ast.Location) error {
	return &Error{
		Code:     WithMergeErr,
		Location: loc,
		Message:  "real and replacement data could not be merged",
	}
}

func internalErr(loc *ast.Location, msg string) error {
	return &Error{
		Code:     InternalErr,
		Location: loc,
		Message:  msg,
	}
}
