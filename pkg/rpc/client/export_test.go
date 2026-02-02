package client

import (
	"net/http"

	rpc "github.com/aquasecurity/trivy/rpc/scanner"
)

// NewTestService creates a Service for testing with injected dependencies.
func NewTestService(remoteURL string, customHeaders http.Header, rpcClient rpc.Scanner, httpClient *http.Client) Service {
	return Service{
		remoteURL:     remoteURL,
		customHeaders: customHeaders,
		client:        rpcClient,
		httpClient:    httpClient,
	}
}
