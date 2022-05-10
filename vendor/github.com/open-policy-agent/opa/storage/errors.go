// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package storage

import (
	"fmt"
)

const (
	// InternalErr indicates an unknown, internal error has occurred.
	InternalErr = "storage_internal_error"

	// NotFoundErr indicates the path used in the storage operation does not
	// locate a document.
	NotFoundErr = "storage_not_found_error"

	// WriteConflictErr indicates a write on the path enocuntered a conflicting
	// value inside the transaction.
	WriteConflictErr = "storage_write_conflict_error"

	// InvalidPatchErr indicates an invalid patch/write was issued. The patch
	// was rejected.
	InvalidPatchErr = "storage_invalid_patch_error"

	// InvalidTransactionErr indicates an invalid operation was performed
	// inside of the transaction.
	InvalidTransactionErr = "storage_invalid_txn_error"

	// TriggersNotSupportedErr indicates the caller attempted to register a
	// trigger against a store that does not support them.
	TriggersNotSupportedErr = "storage_triggers_not_supported_error"

	// WritesNotSupportedErr indicate the caller attempted to perform a write
	// against a store that does not support them.
	WritesNotSupportedErr = "storage_writes_not_supported_error"

	// PolicyNotSupportedErr indicate the caller attempted to perform a policy
	// management operation against a store that does not support them.
	PolicyNotSupportedErr = "storage_policy_not_supported_error"
)

// Error is the error type returned by the storage layer.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (err *Error) Error() string {
	if err.Message != "" {
		return fmt.Sprintf("%v: %v", err.Code, err.Message)
	}
	return string(err.Code)
}

// IsNotFound returns true if this error is a NotFoundErr.
func IsNotFound(err error) bool {
	switch err := err.(type) {
	case *Error:
		return err.Code == NotFoundErr
	}
	return false
}

// IsWriteConflictError returns true if this error a WriteConflictErr.
func IsWriteConflictError(err error) bool {
	switch err := err.(type) {
	case *Error:
		return err.Code == WriteConflictErr
	}
	return false
}

// IsInvalidPatch returns true if this error is a InvalidPatchErr.
func IsInvalidPatch(err error) bool {
	switch err := err.(type) {
	case *Error:
		return err.Code == InvalidPatchErr
	}
	return false
}

// IsInvalidTransaction returns true if this error is a InvalidTransactionErr.
func IsInvalidTransaction(err error) bool {
	switch err := err.(type) {
	case *Error:
		return err.Code == InvalidTransactionErr
	}
	return false
}

// IsIndexingNotSupported is a stub for backwards-compatibility.
//
// Deprecated: We no longer return IndexingNotSupported errors, so it is
// unnecessary to check for them.
func IsIndexingNotSupported(error) bool { return false }

func writeConflictError(path Path) *Error {
	return &Error{
		Code:    WriteConflictErr,
		Message: fmt.Sprint(path),
	}
}

func triggersNotSupportedError() *Error {
	return &Error{
		Code: TriggersNotSupportedErr,
	}
}

func writesNotSupportedError() *Error {
	return &Error{
		Code: WritesNotSupportedErr,
	}
}

func policyNotSupportedError() *Error {
	return &Error{
		Code: PolicyNotSupportedErr,
	}
}
