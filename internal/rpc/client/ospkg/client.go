package ospkg

import (
	"context"
	"net/http"

	"github.com/google/wire"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	r "github.com/aquasecurity/trivy/internal/rpc"
	"github.com/aquasecurity/trivy/internal/rpc/client"
	detector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
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

type Token string

type Detector struct {
	token  Token
	client rpc.OSDetector
}

func NewDetector(token Token, detector rpc.OSDetector) Detector {
	return Detector{token: token, client: detector}
}

func (d Detector) Detect(osFamily, osName string, pkgs []analyzer.Package) ([]types.DetectedVulnerability, error) {
	ctx := client.WithToken(context.Background(), string(d.token))
	res, err := d.client.Detect(ctx, &rpc.OSDetectRequest{
		OsFamily: osFamily,
		OsName:   osName,
		Packages: r.ConvertToRpcPkgs(pkgs),
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to detect vulnerabilities via RPC: %w", err)
	}

	return r.ConvertFromRpcVulns(res.Vulnerabilities), nil
}
