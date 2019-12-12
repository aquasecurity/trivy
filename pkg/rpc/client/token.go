package client

import (
	"context"
	"net/http"

	"github.com/twitchtv/twirp"

	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	buildRequestHeaderFunc = buildRequestHeader
)

func buildRequestHeader(inputHeaders map[string]string) http.Header {
	header := make(http.Header)
	for k, v := range inputHeaders {
		header.Set(k, v)
	}
	return header
}

func WithToken(ctx context.Context, token string) context.Context {
	// Prepare custom header
	header := buildRequestHeaderFunc(map[string]string{"Trivy-Token": token})

	// Attach the headers to a context
	ctxWithToken, err := twirp.WithHTTPRequestHeaders(ctx, header)
	if err != nil {
		log.Logger.Warnf("twirp error setting headers: %s", err)
		return ctx
	}
	return ctxWithToken
}
