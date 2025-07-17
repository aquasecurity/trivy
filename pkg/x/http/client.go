package http

import (
	"context"
	"net/http"
	"time"
)

type ClientOption func(client *http.Client)

func WithTimeout(timeout time.Duration) ClientOption {
	return func(client *http.Client) {
		client.Timeout = timeout
	}
}

func Client(opts ...ClientOption) *http.Client {
	return ClientWithContext(context.Background(), opts...)
}

// ClientWithContext returns an HTTP client with the specified context and options.
func ClientWithContext(ctx context.Context, opts ...ClientOption) *http.Client {
	c := &http.Client{
		Transport: Transport(ctx),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}
