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

package twirp

import (
	"context"
	"errors"
	"net/http"

	"github.com/twitchtv/twirp/internal/contextkeys"
)

// MethodName extracts the name of the method being handled in the given
// context. If it is not known, it returns ("", false).
func MethodName(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(contextkeys.MethodNameKey).(string)
	return name, ok
}

// ServiceName extracts the name of the service handling the given context. If
// it is not known, it returns ("", false).
func ServiceName(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(contextkeys.ServiceNameKey).(string)
	return name, ok
}

// PackageName extracts the fully-qualified protobuf package name of the service
// handling the given context. If it is not known, it returns ("", false). If
// the service comes from a proto file that does not declare a package name, it
// returns ("", true).
//
// Note that the protobuf package name can be very different than the go package
// name; the two are unrelated.
func PackageName(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(contextkeys.PackageNameKey).(string)
	return name, ok
}

// StatusCode retrieves the status code of the response (as string like "200").
// If it is known returns (status, true).
// If it is not known, it returns ("", false).
func StatusCode(ctx context.Context) (string, bool) {
	code, ok := ctx.Value(contextkeys.StatusCodeKey).(string)
	return code, ok
}

// WithHTTPRequestHeaders stores an http.Header in a context.Context. When
// using a Twirp-generated client, you can pass the returned context
// into any of the request methods, and the stored header will be
// included in outbound HTTP requests.
//
// This can be used to set custom HTTP headers like authorization tokens or
// client IDs. But note that HTTP headers are a Twirp implementation detail,
// only visible by middleware, not by the server implementation.
//
// WithHTTPRequestHeaders returns an error if the provided http.Header
// would overwrite a header that is needed by Twirp, like "Content-Type".
func WithHTTPRequestHeaders(ctx context.Context, h http.Header) (context.Context, error) {
	if _, ok := h["Accept"]; ok {
		return nil, errors.New("provided header cannot set Accept")
	}
	if _, ok := h["Content-Type"]; ok {
		return nil, errors.New("provided header cannot set Content-Type")
	}
	if _, ok := h["Twirp-Version"]; ok {
		return nil, errors.New("provided header cannot set Twirp-Version")
	}

	copied := make(http.Header, len(h))
	for k, vv := range h {
		if vv == nil {
			copied[k] = nil
			continue
		}
		copied[k] = make([]string, len(vv))
		copy(copied[k], vv)
	}

	return context.WithValue(ctx, contextkeys.RequestHeaderKey, copied), nil
}

func HTTPRequestHeaders(ctx context.Context) (http.Header, bool) {
	h, ok := ctx.Value(contextkeys.RequestHeaderKey).(http.Header)
	return h, ok
}

// SetHTTPResponseHeader sets an HTTP header key-value pair using a context
// provided by a twirp-generated server, or a child of that context.
// The server will include the header in its response for that request context.
//
// This can be used to respond with custom HTTP headers like "Cache-Control".
// But note that HTTP headers are a Twirp implementation detail,
// only visible by middleware, not by the clients or their responses.
//
// The header will be ignored (noop) if the context is invalid (i.e. using a new
// context.Background() instead of passing the context from the handler).
//
// If called multiple times with the same key, it replaces any existing values
// associated with that key.
//
// SetHTTPResponseHeader returns an error if the provided header key
// would overwrite a header that is needed by Twirp, like "Content-Type".
func SetHTTPResponseHeader(ctx context.Context, key, value string) error {
	if key == "Content-Type" {
		return errors.New("header key can not be Content-Type")
	}

	responseWriter, ok := ctx.Value(contextkeys.ResponseWriterKey).(http.ResponseWriter)
	if ok {
		responseWriter.Header().Set(key, value)
	} // invalid context is ignored, not an error, this is to allow easy unit testing with mock servers

	return nil
}

// AddHTTPResponseHeader behaves like SetHTTPResponseHeader,
// but it appends the key-value pair to the header (instead of replacing it).
//
// AddHTTPResponseHeader returns an error if the key is "Content-Type".
func AddHTTPResponseHeader(ctx context.Context, key, value string) error {
	if key == "Content-Type" {
		return errors.New("header key can not be Content-Type")
	}

	responseWriter, ok := ctx.Value(contextkeys.ResponseWriterKey).(http.ResponseWriter)
	if ok {
		responseWriter.Header().Add(key, value)
	} // invalid context is ignored, not an error, this is to allow easy unit testing with mock servers

	return nil
}
