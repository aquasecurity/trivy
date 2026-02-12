package http

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/aquasecurity/trivy/pkg/version/app"
)

var (
	defaultTransport = NewTransport(Options{})
	mu               sync.RWMutex
)

// wrapper wraps an http.RoundTripper to add custom behavior (e.g., retry, logging).
type wrapper func(http.RoundTripper) http.RoundTripper

// TransportOption modifies an *http.Transport.
type TransportOption func(*http.Transport)

// Transport is an interface for building an http.RoundTripper.
type Transport interface {
	Build(opts ...TransportOption) http.RoundTripper
}

// transport is the default implementation of Transport.
type transport struct {
	base     *http.Transport
	wrappers []wrapper
}

// Build returns an http.RoundTripper with TransportOptions applied and all wrappers applied.
func (t *transport) Build(opts ...TransportOption) http.RoundTripper {
	base := t.base.Clone()
	for _, opt := range opts {
		opt(base)
	}
	var tr http.RoundTripper = base
	for _, wrapper := range t.wrappers {
		tr = wrapper(tr)
	}
	return tr
}

type transportKey struct{}

// WithTransport returns a new context with the given transport.
// This is mainly for testing when a different HTTP transport needs to be used.
func WithTransport(ctx context.Context, t Transport) context.Context {
	return context.WithValue(ctx, transportKey{}, t)
}

// Options configures the transport settings
type Options struct {
	Insecure  bool
	Timeout   time.Duration
	CACerts   *x509.CertPool
	UserAgent string
	TraceHTTP bool
	// Proxy specifies a custom proxy function. In most cases, standard environment variables
	// (HTTP_PROXY, HTTPS_PROXY, NO_PROXY) are sufficient. However, some cases require a custom
	// proxy function, e.g., when using proxy settings from Maven's settings.xml.
	Proxy func(*http.Request) (*url.URL, error)
}

// SetDefaultTransport sets the default transport configuration
func SetDefaultTransport(t Transport) {
	mu.Lock()
	defer mu.Unlock()
	defaultTransport = t
}

// RoundTripper returns the http.RoundTripper from the context, or builds one from the default transport.
// TransportOptions can be used to override the base transport settings for the returned http.RoundTripper only;
// they do not modify the default transport or the transport stored in the context.
func RoundTripper(ctx context.Context, opts ...TransportOption) http.RoundTripper {
	var t Transport
	if ct, ok := ctx.Value(transportKey{}).(Transport); ok {
		t = ct
	} else {
		mu.RLock()
		t = defaultTransport
		mu.RUnlock()
	}
	return t.Build(opts...)
}

// WithInsecure returns a TransportOption that sets InsecureSkipVerify.
func WithInsecure(insecure bool) TransportOption {
	return func(tr *http.Transport) {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		}
		tr.TLSClientConfig.InsecureSkipVerify = insecure
	}
}

// NewTransport creates a new custom Transport with the specified options.
// It should be used to initialize the default transport via SetDefaultTransport.
// In most cases, you should use the `RoundTripper` function to get the http.RoundTripper.
func NewTransport(opts Options) Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()

	// Set timeout (default to 5 minutes)
	timeout := cmp.Or(opts.Timeout, 5*time.Minute)
	d := &net.Dialer{
		Timeout: timeout,
	}
	tr.DialContext = d.DialContext

	if opts.Proxy != nil {
		tr.Proxy = opts.Proxy
	}

	// Configure TLS only when needed.
	if opts.CACerts != nil || opts.Insecure {
		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: opts.Insecure,
			RootCAs:            opts.CACerts,
		}
	}

	userAgent := cmp.Or(opts.UserAgent, fmt.Sprintf("trivy/%s", app.Version()))

	// Apply trace transport first, then user agent transport
	// so that the user agent is set before the request is logged
	rt := &transport{base: tr}
	if opts.TraceHTTP {
		rt.wrappers = append(rt.wrappers, traceWrapper())
	}

	rt.wrappers = append(rt.wrappers, userAgentWrapper(userAgent))
	return rt
}

func traceWrapper() wrapper {
	return func(rt http.RoundTripper) http.RoundTripper {
		return NewTraceTransport(rt)
	}
}

func userAgentWrapper(ua string) wrapper {
	return func(rt http.RoundTripper) http.RoundTripper {
		return NewUserAgent(rt, ua)
	}
}
