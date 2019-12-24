package library

import (
	"context"
	"net/http"

	"github.com/aquasecurity/trivy/pkg/rpc/client"

	"github.com/google/wire"
	"golang.org/x/xerrors"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	detector "github.com/aquasecurity/trivy/pkg/detector/library"
	r "github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/pkg/types"
	rpc "github.com/aquasecurity/trivy/rpc/detector"
)

var SuperSet = wire.NewSet(
	NewProtobufClient,
	NewDetector,
	wire.Bind(new(detector.Operation), new(Detector)),
)

type RemoteURL string

func NewProtobufClient(remoteURL RemoteURL) rpc.LibDetector {
	return rpc.NewLibDetectorProtobufClient(string(remoteURL), &http.Client{})
}

type CustomHeaders http.Header

type Detector struct {
	customHeaders CustomHeaders
	client        rpc.LibDetector
}

func NewDetector(customHeaders CustomHeaders, detector rpc.LibDetector) Detector {
	return Detector{customHeaders: customHeaders, client: detector}
}

func (d Detector) Detect(filePath string, libs []ptypes.Library) ([]types.DetectedVulnerability, error) {
	ctx := client.WithCustomHeaders(context.Background(), http.Header(d.customHeaders))
	res, err := d.client.Detect(ctx, &rpc.LibDetectRequest{
		FilePath:  filePath,
		Libraries: r.ConvertToRpcLibraries(libs),
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to detect vulnerabilities via RPC: %w", err)
	}

	return r.ConvertFromRpcVulns(res.Vulnerabilities), nil
}
