package client

import (
	"context"
	"net/http"

	"github.com/twitchtv/twirp"

	"github.com/aquasecurity/trivy/pkg/log"
)

func WithToken(ctx context.Context, token string) context.Context {
	// Prepare custom header
	header := make(http.Header)
	header.Set("Trivy-Token", token)

	// Attach the headers to a context
	ctx, err := twirp.WithHTTPRequestHeaders(ctx, header)
	if err != nil {
		log.Logger.Warnf("twirp error setting headers: %s", err)
	}
	return ctx
}
