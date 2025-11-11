package http

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aquasecurity/trivy/pkg/log"
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
	Insecure   bool
	Timeout    time.Duration
	CaCertPath string
	UserAgent  string
	TraceHTTP  bool
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

	// Configure TLS only when needed.
	if pool := loadRootCAs(opts.CaCertPath); pool != nil || opts.Insecure {
		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: opts.Insecure,
			RootCAs:            pool,
		}
	}

	userAgent := cmp.Or(opts.UserAgent, fmt.Sprintf("trivy/%s", app.Version()))

	// Apply trace transport first, then user agent transport
	// so that the user agent is set before the request is logged
	var transport http.RoundTripper = tr
	if opts.TraceHTTP {
		transport = NewTraceTransport(transport)
	}

	return NewUserAgent(transport, userAgent)
}

// loadRootCAs builds a cert pool from the system pool and the provided PEM bundle.
// Returns nil if caCertPath is empty or on failure.
func loadRootCAs(caCertPath string) *x509.CertPool {
	if caCertPath == "" {
		return nil
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	pem, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Error("Failed to read CA bundle", log.Err(err), log.FilePath(caCertPath))
		return nil
	}
	if ok := rootCAs.AppendCertsFromPEM(pem); !ok {
		log.Error("Failed to append CA bundle", log.FilePath(caCertPath))
		return nil
	}
	return rootCAs
}
