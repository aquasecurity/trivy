package ospkg

import (
	"context"
	"net/http"

	"github.com/google/wire"

	"github.com/aquasecurity/trivy/internal/rpc/client"

	"github.com/aquasecurity/fanal/analyzer"

	"github.com/aquasecurity/trivy/internal/rpc"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/rpc/detector"
	"golang.org/x/xerrors"
)

var SuperSet = wire.NewSet(
	&http.Client{},
	NewProtobufClient,
	NewDetector,
)

type RemoteURL string

func NewProtobufClient(remoteURL RemoteURL, client *http.Client) detector.OSDetector {
	return detector.NewOSDetectorProtobufClient(string(remoteURL), client)
}

type Token string

type Detector struct {
	token  Token
	client detector.OSDetector
}

func NewDetector(token Token, detector detector.OSDetector) Detector {
	return Detector{token: token, client: detector}
}

func (d Detector) Detect(osFamily, osName string, pkgs []analyzer.Package) ([]types.DetectedVulnerability, error) {
	ctx := client.WithToken(context.Background(), string(d.token))
	res, err := d.client.Detect(ctx, &detector.OSDetectRequest{
		OsFamily: osFamily,
		OsName:   osName,
		Packages: rpc.ConvertToRpcPkgs(pkgs),
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to detect vulnerabilities via RPC: %w", err)
	}

	return rpc.ConvertFromRpcVulns(res.Vulnerabilities), nil
}
