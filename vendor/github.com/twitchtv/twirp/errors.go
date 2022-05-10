// Copyright 2018 Twitch Interactive, Inc.  All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may not
// use this file except in compliance with the License. A copy of the License is
// located at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// or in the "license" file accompanying this file. This file is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

// Package twirp provides core types used in generated Twirp servers and client.
//
// Twirp services handle errors using the `twirp.Error` interface.
//
// For example, a server method may return an InvalidArgumentError:
//
//     if req.Order != "DESC" && req.Order != "ASC" {
//         return nil, twirp.InvalidArgumentError("Order", "must be DESC or ASC")
//     }
//
// And the same twirp.Error is returned by the client, for example:
//
//     resp, err := twirpClient.RPCMethod(ctx, req)
//     if err != nil {
//         if twerr, ok := err.(twirp.Error); ok {
//             switch twerr.Code() {
//             case twirp.InvalidArgument:
//                 log.Error("invalid argument "+twirp.Meta("argument"))
//             default:
//                 log.Error(twerr.Error())
//             }
//         }
//     }
//
// Clients may also return Internal errors if something failed on the system:
// the server, the network, or the client itself (i.e. failure parsing
// response).
//
package twirp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

// Error represents an error in a Twirp service call.
type Error interface {
	// Code is of the valid error codes.
	Code() ErrorCode

	// Msg returns a human-readable, unstructured messages describing the error.
	Msg() string

	// WithMeta returns a copy of the Error with the given key-value pair attached
	// as metadata. If the key is already set, it is overwritten.
	WithMeta(key string, val string) Error

	// Meta returns the stored value for the given key. If the key has no set
	// value, Meta returns an empty string. There is no way to distinguish between
	// an unset value and an explicit empty string.
	Meta(key string) string

	// MetaMap returns the complete key-value metadata map stored on the error.
	MetaMap() map[string]string

	// Error returns a string of the form "twirp error <Type>: <Msg>"
	Error() string
}

// code.Error(msg) builds a new Twirp error with code and msg. Example:
//   twirp.NotFound.Error("Resource not found")
//   twirp.Internal.Error("Oops")
func (code ErrorCode) Error(msg string) Error {
	return NewError(code, msg)
}

// code.Errorf(msg, args...) builds a new Twirp error with code and formatted msg.
// The format may include "%w" to wrap other errors. Examples:
//   twirp.Internal.Error("Oops: %w", originalErr)
//   twirp.NotFound.Error("Resource not found with id: %q", resourceID)
func (code ErrorCode) Errorf(msgFmt string, a ...interface{}) Error {
	return NewErrorf(code, msgFmt, a...)
}

// WrapError allows Twirp errors to wrap other errors.
// The wrapped error can be extracted later with (github.com/pkg/errors).Unwrap
// or errors.Is from the standard errors package on Go 1.13+.
func WrapError(twerr Error, err error) Error {
	return &wrappedErr{
		wrapper: twerr,
		cause:   err,
	}
}

// NewError builds a twirp.Error. The code must be one of the valid predefined constants.
// To add metadata, use .WithMeta(key, value) method after building the error.
func NewError(code ErrorCode, msg string) Error {
	if !IsValidErrorCode(code) {
		return &twerr{code: Internal, msg: "invalid error type " + string(code)}
	}
	return &twerr{code: code, msg: msg}
}

// NewErrorf builds a twirp.Error with a formatted msg.
// The format may include "%w" to wrap other errors. Examples:
//   twirp.NewErrorf(twirp.Internal, "Oops: %w", originalErr)
//   twirp.NewErrorf(twirp.NotFound, "resource with id: %q", resourceID)
func NewErrorf(code ErrorCode, msgFmt string, a ...interface{}) Error {
	err := fmt.Errorf(msgFmt, a...)      // format error message, may include "%w" with an original error
	twerr := NewError(code, err.Error()) // use the error as msg
	return WrapError(twerr, err)         // wrap so the original error can be identified with errors.Is
}

// NotFoundError is a convenience constructor for NotFound errors.
func NotFoundError(msg string) Error {
	return NewError(NotFound, msg)
}

// InvalidArgumentError is a convenience constructor for InvalidArgument errors.
// The argument name is included on the "argument" metadata for convenience.
func InvalidArgumentError(argument string, validationMsg string) Error {
	err := NewError(InvalidArgument, argument+" "+validationMsg)
	err = err.WithMeta("argument", argument)
	return err
}

// RequiredArgumentError builds an InvalidArgument error.
// Useful when a request argument is expected to have a non-zero value.
func RequiredArgumentError(argument string) Error {
	return InvalidArgumentError(argument, "is required")
}

// InternalError is a convenience constructor for Internal errors.
func InternalError(msg string) Error {
	return NewError(Internal, msg)
}

// InternalErrorf uses the formatted message as the internal error msg.
// The format may include "%w" to wrap other errors. Examples:
//   twirp.InternalErrorf("database error: %w", err)
//   twirp.InternalErrorf("failed to load resource %q: %w", resourceID, originalErr)
func InternalErrorf(msgFmt string, a ...interface{}) Error {
	return NewErrorf(Internal, msgFmt, a...)
}

// InternalErrorWith makes an internal error, wrapping the original error and using it
// for the error message, and with metadata "cause" with the original error type.
// This function is used by Twirp services to wrap non-Twirp errors as internal errors.
// The wrapped error can be extracted later with (github.com/pkg/errors).Unwrap
// or errors.Is from the standard errors package on Go 1.13+.
func InternalErrorWith(err error) Error {
	twerr := NewError(Internal, err.Error())
	twerr = twerr.WithMeta("cause", fmt.Sprintf("%T", err)) // to easily tell apart wrapped internal errors from explicit ones
	return WrapError(twerr, err)
}

// ErrorCode represents a Twirp error type.
type ErrorCode string

// Valid Twirp error types. Most error types are equivalent to gRPC status codes
// and follow the same semantics.
const (
	// Canceled indicates the operation was cancelled (typically by the caller).
	Canceled ErrorCode = "canceled"

	// Unknown error. For example when handling errors raised by APIs that do not
	// return enough error information.
	Unknown ErrorCode = "unknown"

	// InvalidArgument indicates client specified an invalid argument. It
	// indicates arguments that are problematic regardless of the state of the
	// system (i.e. a malformed file name, required argument, number out of range,
	// etc.).
	InvalidArgument ErrorCode = "invalid_argument"

	// Malformed indicates an error occurred while decoding the client's request.
	// This may mean that the message was encoded improperly, or that there is a
	// disagreement in message format between the client and server.
	Malformed ErrorCode = "malformed"

	// DeadlineExceeded means operation expired before completion. For operations
	// that change the state of the system, this error may be returned even if the
	// operation has completed successfully (timeout).
	DeadlineExceeded ErrorCode = "deadline_exceeded"

	// NotFound means some requested entity was not found.
	NotFound ErrorCode = "not_found"

	// BadRoute means that the requested URL path wasn't routable to a Twirp
	// service and method. This is returned by the generated server, and usually
	// shouldn't be returned by applications. Instead, applications should use
	// NotFound or Unimplemented.
	BadRoute ErrorCode = "bad_route"

	// AlreadyExists means an attempt to create an entity failed because one
	// already exists.
	AlreadyExists ErrorCode = "already_exists"

	// PermissionDenied indicates the caller does not have permission to execute
	// the specified operation. It must not be used if the caller cannot be
	// identified (Unauthenticated).
	PermissionDenied ErrorCode = "permission_denied"

	// Unauthenticated indicates the request does not have valid authentication
	// credentials for the operation.
	Unauthenticated ErrorCode = "unauthenticated"

	// ResourceExhausted indicates some resource has been exhausted or rate-limited,
	// perhaps a per-user quota, or perhaps the entire file system is out of space.
	ResourceExhausted ErrorCode = "resource_exhausted"

	// FailedPrecondition indicates operation was rejected because the system is
	// not in a state required for the operation's execution. For example, doing
	// an rmdir operation on a directory that is non-empty, or on a non-directory
	// object, or when having conflicting read-modify-write on the same resource.
	FailedPrecondition ErrorCode = "failed_precondition"

	// Aborted indicates the operation was aborted, typically due to a concurrency
	// issue like sequencer check failures, transaction aborts, etc.
	Aborted ErrorCode = "aborted"

	// OutOfRange means operation was attempted past the valid range. For example,
	// seeking or reading past end of a paginated collection.
	//
	// Unlike InvalidArgument, this error indicates a problem that may be fixed if
	// the system state changes (i.e. adding more items to the collection).
	//
	// There is a fair bit of overlap between FailedPrecondition and OutOfRange.
	// We recommend using OutOfRange (the more specific error) when it applies so
	// that callers who are iterating through a space can easily look for an
	// OutOfRange error to detect when they are done.
	OutOfRange ErrorCode = "out_of_range"

	// Unimplemented indicates operation is not implemented or not
	// supported/enabled in this service.
	Unimplemented ErrorCode = "unimplemented"

	// Internal errors. When some invariants expected by the underlying system
	// have been broken. In other words, something bad happened in the library or
	// backend service. Do not confuse with HTTP Internal Server Error; an
	// Internal error could also happen on the client code, i.e. when parsing a
	// server response.
	Internal ErrorCode = "internal"

	// Unavailable indicates the service is currently unavailable. This is a most
	// likely a transient condition and may be corrected by retrying with a
	// backoff.
	Unavailable ErrorCode = "unavailable"

	// DataLoss indicates unrecoverable data loss or corruption.
	DataLoss ErrorCode = "data_loss"

	// NoError is the zero-value, is considered an empty error and should not be
	// used.
	NoError ErrorCode = ""
)

// ServerHTTPStatusFromErrorCode maps a Twirp error type into a similar HTTP
// response status. It is used by the Twirp server handler to set the HTTP
// response status code. Returns 0 if the ErrorCode is invalid.
func ServerHTTPStatusFromErrorCode(code ErrorCode) int {
	switch code {
	case Canceled:
		return 408 // RequestTimeout
	case Unknown:
		return 500 // Internal Server Error
	case InvalidArgument:
		return 400 // BadRequest
	case Malformed:
		return 400 // BadRequest
	case DeadlineExceeded:
		return 408 // RequestTimeout
	case NotFound:
		return 404 // Not Found
	case BadRoute:
		return 404 // Not Found
	case AlreadyExists:
		return 409 // Conflict
	case PermissionDenied:
		return 403 // Forbidden
	case Unauthenticated:
		return 401 // Unauthorized
	case ResourceExhausted:
		return 429 // Too Many Requests
	case FailedPrecondition:
		return 412 // Precondition Failed
	case Aborted:
		return 409 // Conflict
	case OutOfRange:
		return 400 // Bad Request
	case Unimplemented:
		return 501 // Not Implemented
	case Internal:
		return 500 // Internal Server Error
	case Unavailable:
		return 503 // Service Unavailable
	case DataLoss:
		return 500 // Internal Server Error
	case NoError:
		return 200 // OK
	default:
		return 0 // Invalid!
	}
}

// IsValidErrorCode returns true if is one of the valid predefined constants.
func IsValidErrorCode(code ErrorCode) bool {
	return ServerHTTPStatusFromErrorCode(code) != 0
}

// twirp.Error implementation
type twerr struct {
	code ErrorCode
	msg  string
	meta map[string]string
}

func (e *twerr) Code() ErrorCode { return e.code }
func (e *twerr) Msg() string     { return e.msg }

func (e *twerr) Meta(key string) string {
	if e.meta != nil {
		return e.meta[key] // also returns "" if key is not in meta map
	}
	return ""
}

func (e *twerr) WithMeta(key string, value string) Error {
	newErr := &twerr{
		code: e.code,
		msg:  e.msg,
		meta: make(map[string]string, len(e.meta)),
	}
	for k, v := range e.meta {
		newErr.meta[k] = v
	}
	newErr.meta[key] = value
	return newErr
}

func (e *twerr) MetaMap() map[string]string {
	return e.meta
}

func (e *twerr) Error() string {
	return fmt.Sprintf("twirp error %s: %s", e.code, e.msg)
}

// wrappedErr is the error returned by twirp.InternalErrorWith(err), which is used by clients.
// Implements Unwrap() to allow go 1.13+ errors.Is/As checks,
// and Cause() to allow (github.com/pkg/errors).Unwrap.
type wrappedErr struct {
	wrapper Error
	cause   error
}

func (e *wrappedErr) Code() ErrorCode            { return e.wrapper.Code() }
func (e *wrappedErr) Msg() string                { return e.wrapper.Msg() }
func (e *wrappedErr) Meta(key string) string     { return e.wrapper.Meta(key) }
func (e *wrappedErr) MetaMap() map[string]string { return e.wrapper.MetaMap() }
func (e *wrappedErr) Error() string              { return e.wrapper.Error() }
func (e *wrappedErr) WithMeta(key string, val string) Error {
	return &wrappedErr{
		wrapper: e.wrapper.WithMeta(key, val),
		cause:   e.cause,
	}
}
func (e *wrappedErr) Unwrap() error { return e.cause } // for go1.13 + errors.Is/As
func (e *wrappedErr) Cause() error  { return e.cause } // for github.com/pkg/errors

// WriteError writes an HTTP response with a valid Twirp error format (code, msg, meta).
// Useful outside of the Twirp server (e.g. http middleware).
// If err is not a twirp.Error, it will get wrapped with twirp.InternalErrorWith(err)
func WriteError(resp http.ResponseWriter, err error) error {
	var twerr Error
	if !errors.As(err, &twerr) {
		twerr = InternalErrorWith(err)
	}

	statusCode := ServerHTTPStatusFromErrorCode(twerr.Code())
	respBody := marshalErrorToJSON(twerr)

	resp.Header().Set("Content-Type", "application/json") // Error responses are always JSON
	resp.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	resp.WriteHeader(statusCode) // set HTTP status code and send response

	_, writeErr := resp.Write(respBody)
	if writeErr != nil {
		return writeErr
	}
	return nil
}

// JSON serialization for errors
type twerrJSON struct {
	Code string            `json:"code"`
	Msg  string            `json:"msg"`
	Meta map[string]string `json:"meta,omitempty"`
}

// marshalErrorToJSON returns JSON from a twirp.Error, that can be used as HTTP error response body.
// If serialization fails, it will use a descriptive Internal error instead.
func marshalErrorToJSON(twerr Error) []byte {
	// make sure that msg is not too large
	msg := twerr.Msg()
	if len(msg) > 1e6 {
		msg = msg[:1e6]
	}

	tj := twerrJSON{
		Code: string(twerr.Code()),
		Msg:  msg,
		Meta: twerr.MetaMap(),
	}

	buf, err := json.Marshal(&tj)
	if err != nil {
		buf = []byte("{\"type\": \"" + Internal + "\", \"msg\": \"There was an error but it could not be serialized into JSON\"}") // fallback
	}

	return buf
}
