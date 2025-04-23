package client

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/samber/lo"
	"github.com/twitchtv/twirp"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	r "github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/pkg/types"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
	"github.com/aquasecurity/trivy/rpc/common"
	rpc "github.com/aquasecurity/trivy/rpc/scanner"
)

type options struct {
	rpcClient rpc.Scanner
}

type Option func(*options)

// WithRPCClient takes rpc client for testability
func WithRPCClient(c rpc.Scanner) Option {
	return func(opts *options) {
		opts.rpcClient = c
	}
}

// ServiceOption holds options for RPC client
type ServiceOption struct {
	RemoteURL     string
	Insecure      bool
	CustomHeaders http.Header
	PathPrefix    string
}

// Service implements the RPC client for remote scanning
type Service struct {
	customHeaders http.Header
	client        rpc.Scanner
}

// NewService is the factory method to return RPC Service
func NewService(scannerOptions ServiceOption, opts ...Option) Service {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: scannerOptions.Insecure}
	httpClient := &http.Client{Transport: tr}

	var twirpOpts []twirp.ClientOption
	if scannerOptions.PathPrefix != "" {
		twirpOpts = append(twirpOpts, twirp.WithClientPathPrefix(scannerOptions.PathPrefix))
	}
	c := rpc.NewScannerProtobufClient(scannerOptions.RemoteURL, httpClient, twirpOpts...)

	o := &options{rpcClient: c}
	for _, opt := range opts {
		opt(o)
	}

	return Service{
		customHeaders: scannerOptions.CustomHeaders,
		client:        o.rpcClient,
	}
}

// Scan scans the image
func (s Service) Scan(ctx context.Context, target, artifactKey string, blobKeys []string, opts types.ScanOptions) (types.ScanResponse, error) {
	ctx = WithCustomHeaders(ctx, s.customHeaders)

	// Convert to the rpc struct
	licenseCategories := make(map[string]*rpc.Licenses)
	for category, names := range opts.LicenseCategories {
		licenseCategories[string(category)] = &rpc.Licenses{Names: names}
	}

	var distro *common.OS
	if !lo.IsEmpty(opts.Distro) {
		distro = &common.OS{
			Family: string(opts.Distro.Family),
			Name:   opts.Distro.Name,
		}
	}

	var res *rpc.ScanResponse
	err := r.Retry(func() error {
		var err error
		res, err = s.client.Scan(ctx, &rpc.ScanRequest{
			Target:     target,
			ArtifactId: artifactKey,
			BlobIds:    blobKeys,
			Options: &rpc.ScanOptions{
				PkgTypes:            opts.PkgTypes,
				PkgRelationships:    xstrings.ToStringSlice(opts.PkgRelationships),
				Scanners:            xstrings.ToStringSlice(opts.Scanners),
				LicenseCategories:   licenseCategories,
				LicenseFull:         opts.LicenseFull,
				IncludeDevDeps:      opts.IncludeDevDeps,
				Distro:              distro,
				VulnSeveritySources: xstrings.ToStringSlice(opts.VulnSeveritySources),
			},
		})
		return err
	})
	if err != nil {
		return types.ScanResponse{}, xerrors.Errorf("failed to detect vulnerabilities via RPC: %w", err)
	}

	return types.ScanResponse{
		Results: r.ConvertFromRPCResults(res.Results),
		OS:      r.ConvertFromRPCOS(res.Os),
		Layers: lo.FilterMap(res.Layers, func(layer *common.Layer, _ int) (ftypes.Layer, bool) {
			if layer == nil {
				return ftypes.Layer{}, false
			}
			return r.ConvertFromRPCLayer(layer), true
		}),
	}, nil
}
