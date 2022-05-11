// Copyright 2021 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package tracing enables dependency-injection at runtime. When used
// together with an underscore-import of `github.com/open-policy-agent/opa/features/tracing`,
// the server and its runtime will emit OpenTelemetry spans to the
// configured sink.
package tracing

import "net/http"

// Options are options for the HTTPTracingService, passed along as-is.
type Options []interface{}

// NewOptions is a helper method for constructing `tracing.Options`
func NewOptions(opts ...interface{}) Options {
	return opts
}

// HTTPTracingService defines how distributed tracing comes in, server- and client-side
type HTTPTracingService interface {
	// NewTransport is used when setting up an HTTP client
	NewTransport(http.RoundTripper, Options) http.RoundTripper

	// NewHandler is used to wrap an http.Handler in the server
	NewHandler(http.Handler, string, Options) http.Handler
}

var tracing HTTPTracingService

// RegisterHTTPTracing enables a HTTPTracingService for further use.
func RegisterHTTPTracing(ht HTTPTracingService) {
	tracing = ht
}

// NewTransport returns another http.RoundTripper, instrumented to emit tracing
// spans according to Options. Provided by the HTTPTracingService registered with
// this package via RegisterHTTPTracing.
func NewTransport(tr http.RoundTripper, opts Options) http.RoundTripper {
	if tracing == nil {
		return tr
	}
	return tracing.NewTransport(tr, opts)
}

// NewHandler returns another http.Handler, instrumented to emit tracing spans
// according to Options. Provided by the HTTPTracingService registered with
// this package via RegisterHTTPTracing.
func NewHandler(f http.Handler, label string, opts Options) http.Handler {
	if tracing == nil {
		return f
	}
	return tracing.NewHandler(f, label, opts)
}
