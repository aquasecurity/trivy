package client

import (
	"context"
	"crypto/tls"
	"net/http"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	r "github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/pkg/types"
	rpc "github.com/aquasecurity/trivy/rpc/scanner"
)

type options struct {
	rpcClient rpc.Scanner
}

type option func(*options)

// WithRPCClient takes rpc client for testability
func WithRPCClient(c rpc.Scanner) option {
	return func(opts *options) {
		opts.rpcClient = c
	}
}

// ScannerOption holds options for RPC client
type ScannerOption struct {
	RemoteURL     string
	Insecure      bool
	CustomHeaders http.Header
}

// Scanner implements the RPC scanner
type Scanner struct {
	customHeaders http.Header
	client        rpc.Scanner
}

// NewScanner is the factory method to return RPC Scanner
func NewScanner(scannerOptions ScannerOption, opts ...option) Scanner {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: scannerOptions.Insecure,
			},
		},
	}

	c := rpc.NewScannerProtobufClient(scannerOptions.RemoteURL, httpClient)

	o := &options{rpcClient: c}
	for _, opt := range opts {
		opt(o)
	}

	return Scanner{customHeaders: scannerOptions.CustomHeaders, client: o.rpcClient}
}

// Scan scans the image
func (s Scanner) Scan(target, artifactKey string, blobKeys []string, options types.ScanOptions) (types.Results, *ftypes.OS, error) {
	ctx := WithCustomHeaders(context.Background(), s.customHeaders)

	var res *rpc.ScanResponse
	err := r.Retry(func() error {
		var err error
		res, err = s.client.Scan(ctx, &rpc.ScanRequest{
			Target:     target,
			ArtifactId: artifactKey,
			BlobIds:    blobKeys,
			Options: &rpc.ScanOptions{
				VulnType:        options.VulnType,
				SecurityChecks:  options.SecurityChecks,
				ListAllPackages: options.ListAllPackages,
			},
		})
		return err
	})
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to detect vulnerabilities via RPC: %w", err)
	}

	return r.ConvertFromRPCResults(res.Results), r.ConvertFromRPCOS(res.Os), nil
}
