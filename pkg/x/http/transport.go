package http

import (
	"cmp"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/aquasecurity/trivy/pkg/version/app"
)

var (
	defaultTransport = NewTransport(Options{})
	mu               sync.RWMutex
)

type transportKey struct{}

// WithTransport returns a new context with the given transport.
// This is mainly for testing when a different HTTP transport needs to be used.
func WithTransport(ctx context.Context, tr http.RoundTripper) context.Context {
	return context.WithValue(ctx, transportKey{}, tr)
}

// Options configures the transport settings
type Options struct {
	Insecure  bool
	Timeout   time.Duration
	UserAgent string
}

// SetDefaultTransport sets the default transport configuration
func SetDefaultTransport(tr http.RoundTripper) {
	mu.Lock()
	defer mu.Unlock()
	defaultTransport = tr
}

// Transport returns the transport from the context, or the default transport if none is set.
func Transport(ctx context.Context) http.RoundTripper {
	t, ok := ctx.Value(transportKey{}).(http.RoundTripper)
	if ok {
		// If the transport is already set in the context, return it.
		return t
	}

	mu.RLock()
	defer mu.RUnlock()

	return defaultTransport
}

// NewTransport creates a new HTTP transport with the specified options.
// It should be used to initialize the default transport.
// In most cases, you should use the `Transport` function to get the default transport.
func NewTransport(opts Options) http.RoundTripper {
	tr := http.DefaultTransport.(*http.Transport).Clone()

	// Set timeout (default to 5 minutes)
	timeout := cmp.Or(opts.Timeout, 5*time.Minute)
	d := &net.Dialer{
		Timeout: timeout,
	}
	tr.DialContext = d.DialContext

	// Configure TLS
	if opts.Insecure {
		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: opts.Insecure,
		}
	}

	userAgent := cmp.Or(opts.UserAgent, fmt.Sprintf("trivy/%s", app.Version()))
	return NewUserAgent(tr, userAgent)
}
