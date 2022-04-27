// Copyright 2018 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transport

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// The set of query string keys that we expect to send as part of the registry
// protocol. Anything else is potentially dangerous to leak, as it's probably
// from a redirect. These redirects often included tokens or signed URLs.
var paramAllowlist = map[string]struct{}{
	// Token exchange
	"scope":   {},
	"service": {},
	// Cross-repo mounting
	"mount": {},
	"from":  {},
	// Layer PUT
	"digest": {},
	// Listing tags and catalog
	"n":    {},
	"last": {},
}

// Error implements error to support the following error specification:
// https://github.com/docker/distribution/blob/master/docs/spec/api.md#errors
type Error struct {
	Errors []Diagnostic `json:"errors,omitempty"`
	// The http status code returned.
	StatusCode int
	// The request that failed.
	Request *http.Request
	// The raw body if we couldn't understand it.
	rawBody string
}

// Check that Error implements error
var _ error = (*Error)(nil)

// Error implements error
func (e *Error) Error() string {
	prefix := ""
	if e.Request != nil {
		prefix = fmt.Sprintf("%s %s: ", e.Request.Method, redactURL(e.Request.URL))
	}
	return prefix + e.responseErr()
}

func (e *Error) responseErr() string {
	switch len(e.Errors) {
	case 0:
		if len(e.rawBody) == 0 {
			if e.Request != nil && e.Request.Method == http.MethodHead {
				return fmt.Sprintf("unexpected status code %d %s (HEAD responses have no body, use GET for details)", e.StatusCode, http.StatusText(e.StatusCode))
			}
			return fmt.Sprintf("unexpected status code %d %s", e.StatusCode, http.StatusText(e.StatusCode))
		}
		return fmt.Sprintf("unexpected status code %d %s: %s", e.StatusCode, http.StatusText(e.StatusCode), e.rawBody)
	case 1:
		return e.Errors[0].String()
	default:
		var errors []string
		for _, d := range e.Errors {
			errors = append(errors, d.String())
		}
		return fmt.Sprintf("multiple errors returned: %s",
			strings.Join(errors, "; "))
	}
}

// Temporary returns whether the request that preceded the error is temporary.
func (e *Error) Temporary() bool {
	if len(e.Errors) == 0 {
		_, ok := temporaryStatusCodes[e.StatusCode]
		return ok
	}
	for _, d := range e.Errors {
		if _, ok := temporaryErrorCodes[d.Code]; !ok {
			return false
		}
	}
	return true
}

// TODO(jonjohnsonjr): Consider moving to internal/redact.
func redactURL(original *url.URL) *url.URL {
	qs := original.Query()
	for k, v := range qs {
		for i := range v {
			if _, ok := paramAllowlist[k]; !ok {
				// key is not in the Allowlist
				v[i] = "REDACTED"
			}
		}
	}
	redacted := *original
	redacted.RawQuery = qs.Encode()
	return &redacted
}

// Diagnostic represents a single error returned by a Docker registry interaction.
type Diagnostic struct {
	Code    ErrorCode   `json:"code"`
	Message string      `json:"message,omitempty"`
	Detail  interface{} `json:"detail,omitempty"`
}

// String stringifies the Diagnostic in the form: $Code: $Message[; $Detail]
func (d Diagnostic) String() string {
	msg := fmt.Sprintf("%s: %s", d.Code, d.Message)
	if d.Detail != nil {
		msg = fmt.Sprintf("%s; %v", msg, d.Detail)
	}
	return msg
}

// ErrorCode is an enumeration of supported error codes.
type ErrorCode string

// The set of error conditions a registry may return:
// https://github.com/docker/distribution/blob/master/docs/spec/api.md#errors-2
const (
	BlobUnknownErrorCode         ErrorCode = "BLOB_UNKNOWN"
	BlobUploadInvalidErrorCode   ErrorCode = "BLOB_UPLOAD_INVALID"
	BlobUploadUnknownErrorCode   ErrorCode = "BLOB_UPLOAD_UNKNOWN"
	DigestInvalidErrorCode       ErrorCode = "DIGEST_INVALID"
	ManifestBlobUnknownErrorCode ErrorCode = "MANIFEST_BLOB_UNKNOWN"
	ManifestInvalidErrorCode     ErrorCode = "MANIFEST_INVALID"
	ManifestUnknownErrorCode     ErrorCode = "MANIFEST_UNKNOWN"
	ManifestUnverifiedErrorCode  ErrorCode = "MANIFEST_UNVERIFIED"
	NameInvalidErrorCode         ErrorCode = "NAME_INVALID"
	NameUnknownErrorCode         ErrorCode = "NAME_UNKNOWN"
	SizeInvalidErrorCode         ErrorCode = "SIZE_INVALID"
	TagInvalidErrorCode          ErrorCode = "TAG_INVALID"
	UnauthorizedErrorCode        ErrorCode = "UNAUTHORIZED"
	DeniedErrorCode              ErrorCode = "DENIED"
	UnsupportedErrorCode         ErrorCode = "UNSUPPORTED"
	TooManyRequestsErrorCode     ErrorCode = "TOOMANYREQUESTS"
	UnknownErrorCode             ErrorCode = "UNKNOWN"
)

// TODO: Include other error types.
var temporaryErrorCodes = map[ErrorCode]struct{}{
	BlobUploadInvalidErrorCode: {},
	TooManyRequestsErrorCode:   {},
	UnknownErrorCode:           {},
}

var temporaryStatusCodes = map[int]struct{}{
	http.StatusRequestTimeout:      {},
	http.StatusInternalServerError: {},
	http.StatusBadGateway:          {},
	http.StatusServiceUnavailable:  {},
	http.StatusGatewayTimeout:      {},
}

// CheckError returns a structured error if the response status is not in codes.
func CheckError(resp *http.Response, codes ...int) error {
	for _, code := range codes {
		if resp.StatusCode == code {
			// This is one of the supported status codes.
			return nil
		}
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// https://github.com/docker/distribution/blob/master/docs/spec/api.md#errors
	structuredError := &Error{}

	// This can fail if e.g. the response body is not valid JSON. That's fine,
	// we'll construct an appropriate error string from the body and status code.
	_ = json.Unmarshal(b, structuredError)

	structuredError.rawBody = string(b)
	structuredError.StatusCode = resp.StatusCode
	structuredError.Request = resp.Request

	return structuredError
}
