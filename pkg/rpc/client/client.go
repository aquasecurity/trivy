package client

import (
	"context"
	"net/http"

	"github.com/caarlos0/env/v6"

	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/google/wire"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	r "github.com/aquasecurity/trivy/pkg/rpc"
	rpc "github.com/aquasecurity/trivy/rpc/scanner"
)

// SuperSet binds the dependencies for RPC client
var SuperSet = wire.NewSet(
	NewProtobufClient,
	NewScanner,
)

// RemoteURL for RPC remote host
type RemoteURL string

// HTTPClientConfig holds the config of the HTTPClient
type HTTPClientConfig struct {
	Insecure bool `env:"TRIVY_INSECURE" envDefault:"false"`
}

// NewProtobufClient is the factory method to return RPC scanner
func NewProtobufClient(remoteURL RemoteURL) (rpc.Scanner, error) {
	httpClientConfig := HTTPClientConfig{}
	if err := env.Parse(&httpClientConfig); err != nil {
		return nil, xerrors.Errorf("unable to parse environment variables: %w", err)
	}

	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := httpTransport.TLSClientConfig.Clone()
	tlsConfig.InsecureSkipVerify = httpClientConfig.Insecure
	httpTransport.TLSClientConfig = tlsConfig

	http.DefaultTransport.(*http.Transport).TLSClientConfig = tlsConfig
	return rpc.NewScannerProtobufClient(string(remoteURL), &http.Client{}), nil
}

// CustomHeaders for holding HTTP headers
type CustomHeaders http.Header

// Scanner implements the RPC scanner
type Scanner struct {
	customHeaders CustomHeaders
	client        rpc.Scanner
}

// NewScanner is the factory method to return RPC Scanner
func NewScanner(customHeaders CustomHeaders, s rpc.Scanner) Scanner {
	return Scanner{customHeaders: customHeaders, client: s}
}

// Scan scans the image
func (s Scanner) Scan(target, artifactKey string, blobKeys []string, options types.ScanOptions) (types.Results, *ftypes.OS, error) {
	ctx := WithCustomHeaders(context.Background(), http.Header(s.customHeaders))

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
