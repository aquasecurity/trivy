package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"

	"github.com/samber/lo"
	"github.com/twitchtv/twirp"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	r "github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/pkg/types"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
	"github.com/aquasecurity/trivy/pkg/x/slices"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
	"github.com/aquasecurity/trivy/rpc/common"
	rpc "github.com/aquasecurity/trivy/rpc/scanner"
)

// ServiceOption holds options for RPC client
type ServiceOption struct {
	RemoteURL     string
	CustomHeaders http.Header
	PathPrefix    string
}

// Service implements the RPC client for remote scanning
type Service struct {
	remoteURL     string
	customHeaders http.Header
	client        rpc.Scanner
	httpClient    *http.Client
}

// NewService is the factory method to return RPC Service
func NewService(scannerOptions ServiceOption) Service {
	httpClient := xhttp.Client()

	var twirpOpts []twirp.ClientOption
	if scannerOptions.PathPrefix != "" {
		twirpOpts = append(twirpOpts, twirp.WithClientPathPrefix(scannerOptions.PathPrefix))
	}

	return Service{
		remoteURL:     scannerOptions.RemoteURL,
		customHeaders: scannerOptions.CustomHeaders,
		client:        rpc.NewScannerProtobufClient(scannerOptions.RemoteURL, httpClient, twirpOpts...),
		httpClient:    httpClient,
	}
}

// Scan scans the image
func (s Service) Scan(ctx context.Context, target, artifactKey string, blobKeys []string, opts types.ScanOptions) (types.ScanResponse, error) {
	ctx = WithCustomHeaders(ctx, s.customHeaders)

	// Fetch server version info in background
	var serverInfo types.VersionInfo
	var wg sync.WaitGroup
	wg.Go(func() {
		info, err := s.serverVersion(ctx)
		if err != nil {
			log.Warn("Failed to fetch server version", log.Err(err))
			return
		}
		serverInfo = info
	})

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

	// Wait for server version fetch to complete
	wg.Wait()

	return types.ScanResponse{
		Results: r.ConvertFromRPCResults(res.Results),
		OS:      r.ConvertFromRPCOS(res.Os),
		Layers: slices.ZeroToNil(lo.FilterMap(res.Layers, func(layer *common.Layer, _ int) (ftypes.Layer, bool) {
			if layer == nil {
				return ftypes.Layer{}, false
			}
			return r.ConvertFromRPCLayer(layer), true
		})),
		ServerInfo: serverInfo,
	}, nil
}

// serverVersion fetches version information from the Trivy server.
// TODO: Consider migrating to RPC in the future for consistency with other server communication.
func (s Service) serverVersion(ctx context.Context) (types.VersionInfo, error) {
	baseURL, err := url.Parse(s.remoteURL)
	if err != nil {
		return types.VersionInfo{}, xerrors.Errorf("failed to parse remote URL: %w", err)
	}
	versionURL := baseURL.ResolveReference(&url.URL{Path: "version"})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL.String(), http.NoBody)
	if err != nil {
		return types.VersionInfo{}, xerrors.Errorf("failed to create request: %w", err)
	}

	// Add custom headers
	for key, values := range s.customHeaders {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return types.VersionInfo{}, xerrors.Errorf("failed to fetch server version: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return types.VersionInfo{}, xerrors.Errorf("server returned status %d", resp.StatusCode)
	}

	var versionInfo types.VersionInfo
	if err := json.NewDecoder(resp.Body).Decode(&versionInfo); err != nil {
		return types.VersionInfo{}, xerrors.Errorf("failed to decode version info: %w", err)
	}

	return versionInfo, nil
}
