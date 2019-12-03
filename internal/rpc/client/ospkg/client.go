package ospkg

import (
	"context"
	"net/http"

	"github.com/aquasecurity/trivy/internal/rpc/client"

	"github.com/aquasecurity/fanal/analyzer"

	"github.com/aquasecurity/trivy/internal/rpc"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/rpc/detector"
	"golang.org/x/xerrors"
)

type DetectClient struct {
	token  string
	client detector.OSDetector
}

func NewDetectClient(remoteURL, token string) DetectClient {
	client := detector.NewOSDetectorProtobufClient(remoteURL, &http.Client{})
	return DetectClient{token: token, client: client}
}

func (d DetectClient) Detect(osFamily, osName string, pkgs []analyzer.Package) ([]types.DetectedVulnerability, error) {
	ctx := context.Background()
	res, err := d.client.Detect(client.WithToken(ctx, d.token), &detector.OSDetectRequest{
		OsFamily: osFamily,
		OsName:   osName,
		Packages: rpc.ConvertToRpcPkgs(pkgs),
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to detect vulnerabilities via RPC: %w", err)
	}

	return rpc.ConvertFromRpcVulns(res.Vulnerabilities), nil
}
