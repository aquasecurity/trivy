package client

import (
	"context"
	"net/http"

	"github.com/twitchtv/twirp"

	"github.com/aquasecurity/trivy/pkg/log"
)

// WithCustomHeaders adds custom headers to request headers
func WithCustomHeaders(ctx context.Context, customHeaders http.Header) context.Context {
	// Attach the headers to a context
	ctxWithToken, err := twirp.WithHTTPRequestHeaders(ctx, customHeaders)
	if err != nil {
		log.Warn("twirp error setting headers", log.Err(err))
		return ctx
	}
	return ctxWithToken
}
