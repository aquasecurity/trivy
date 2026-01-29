package http_test

import (
	"bytes"
	"io"
	"net/http"
)

// RequestRecorder is a test helper that records a single HTTP request sent through a RoundTripper
type RequestRecorder struct {
	request  *http.Request
	response *http.Response
	err      error
}

// RequestRecorderOption is a functional option for RequestRecorder
type RequestRecorderOption func(*RequestRecorder)

// WithResponse sets the response to return
func WithResponse(resp *http.Response) RequestRecorderOption {
	return func(rr *RequestRecorder) {
		rr.response = resp
	}
}

// WithError sets the error to return
func WithError(err error) RequestRecorderOption {
	return func(rr *RequestRecorder) {
		rr.err = err
	}
}

// NewRequestRecorder creates a new RequestRecorder with optional configuration
func NewRequestRecorder(opts ...RequestRecorderOption) *RequestRecorder {
	rr := &RequestRecorder{
		response: &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(nil)),
		},
	}

	for _, opt := range opts {
		opt(rr)
	}

	return rr
}

// RoundTrip implements http.RoundTripper and records the request
func (rr *RequestRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	// Record the request
	rr.request = req

	if rr.err != nil {
		return nil, rr.err
	}

	if rr.response != nil {
		rr.response.Request = req
	}

	return rr.response, nil
}

// Request returns the recorded request
func (rr *RequestRecorder) Request() *http.Request {
	return rr.request
}
