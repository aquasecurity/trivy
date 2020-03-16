package client

import (
	"context"
	"net/http"

	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/google/wire"
	digest "github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	r "github.com/aquasecurity/trivy/pkg/rpc"
	rpc "github.com/aquasecurity/trivy/rpc/scanner"
)

var SuperSet = wire.NewSet(
	NewProtobufClient,
	NewScanner,
)

type RemoteURL string

func NewProtobufClient(remoteURL RemoteURL) rpc.Scanner {
	return rpc.NewScannerProtobufClient(string(remoteURL), &http.Client{})
}

type CustomHeaders http.Header

type Scanner struct {
	customHeaders CustomHeaders
	client        rpc.Scanner
}

func NewScanner(customHeaders CustomHeaders, s rpc.Scanner) Scanner {
	return Scanner{customHeaders: customHeaders, client: s}
}

func (s Scanner) Scan(target string, imageID digest.Digest, layerIDs []string, options types.ScanOptions) (report.Results, *ftypes.OS, bool, error) {
	ctx := WithCustomHeaders(context.Background(), http.Header(s.customHeaders))

	var res *rpc.ScanResponse
	err := r.Retry(func() error {
		var err error
		res, err = s.client.Scan(ctx, &rpc.ScanRequest{
			Target:   target,
			ImageId:  string(imageID),
			LayerIds: layerIDs,
			Options: &rpc.ScanOptions{
				VulnType: options.VulnType,
			},
		})
		return err
	})
	if err != nil {
		return nil, nil, false, xerrors.Errorf("failed to detect vulnerabilities via RPC: %w", err)
	}

	return r.ConvertFromRpcResults(res.Results), r.ConvertFromRpcOS(res.Os), res.Eosl, nil
}
