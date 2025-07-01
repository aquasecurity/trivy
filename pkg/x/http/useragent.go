package http

import (
	"net/http"
)

type userAgentTransport struct {
	inner http.RoundTripper
	ua    string
}

// NewUserAgent returns an http.Roundtripper that sets the user agent
//
// User-Agent: trivy/v0.64.0
func NewUserAgent(inner http.RoundTripper, ua string) http.RoundTripper {
	return &userAgentTransport{
		inner: inner,
		ua:    ua,
	}
}

// RoundTrip implements http.RoundTripper
func (ut *userAgentTransport) RoundTrip(in *http.Request) (*http.Response, error) {
	if ut.ua != "" {
		in.Header.Set("User-Agent", ut.ua)
	}
	return ut.inner.RoundTrip(in)
}
