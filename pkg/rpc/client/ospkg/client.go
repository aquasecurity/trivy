package ospkg

import (
	"context"
	"net/http"

	"github.com/google/wire"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	detector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	r "github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/types"
	rpc "github.com/aquasecurity/trivy/rpc/detector"
)

var SuperSet = wire.NewSet(
	NewProtobufClient,
	NewDetector,
	wire.Bind(new(detector.Operation), new(Detector)),
)

type RemoteURL string

func NewProtobufClient(remoteURL RemoteURL) rpc.OSDetector {
	return rpc.NewOSDetectorProtobufClient(string(remoteURL), &http.Client{})
}

type CustomHeaders http.Header

type Detector struct {
	customHeaders CustomHeaders
	client        rpc.OSDetector
}

func NewDetector(customHeaders CustomHeaders, detector rpc.OSDetector) Detector {
	return Detector{customHeaders: customHeaders, client: detector}
}

func (d Detector) Detect(osFamily, osName string, pkgs []analyzer.Package) ([]types.DetectedVulnerability, bool, error) {
	ctx := client.WithCustomHeaders(context.Background(), http.Header(d.customHeaders))

	var res *rpc.DetectResponse
	err := r.Retry(func() error {
		var err error
		res, err = d.client.Detect(ctx, &rpc.OSDetectRequest{
			OsFamily: osFamily,
			OsName:   osName,
			Packages: r.ConvertToRpcPkgs(pkgs),
		})
		return err
	})
	if err != nil {
		return nil, false, xerrors.Errorf("failed to detect vulnerabilities via RPC: %w", err)
	}

	return r.ConvertFromRpcVulns(res.Vulnerabilities), res.Eosl, nil
}
