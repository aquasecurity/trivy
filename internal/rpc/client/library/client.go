package library

import (
	"context"
	"net/http"

	"github.com/google/wire"

	"github.com/aquasecurity/trivy/internal/rpc/client"

	r "github.com/aquasecurity/trivy/internal/rpc"
	"github.com/aquasecurity/trivy/pkg/types"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	rpc "github.com/aquasecurity/trivy/rpc/detector"
	"golang.org/x/xerrors"
)

var SuperSet = wire.NewSet(
	wire.Struct(new(http.Client)),
	NewProtobufClient,
	NewDetector,
)

type RemoteURL string

func NewProtobufClient(remoteURL RemoteURL, client *http.Client) rpc.LibDetector {
	return rpc.NewLibDetectorProtobufClient(string(remoteURL), client)
}

type Token string

type Detector struct {
	token  Token
	client rpc.LibDetector
}

func NewDetector(token Token, detector rpc.LibDetector) Detector {
	return Detector{token: token, client: detector}
}

func (d Detector) Detect(filePath string, libs []ptypes.Library) ([]types.DetectedVulnerability, error) {
	ctx := client.WithToken(context.Background(), string(d.token))
	res, err := d.client.Detect(ctx, &rpc.LibDetectRequest{
		FilePath:  filePath,
		Libraries: r.ConvertToRpcLibraries(libs),
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to detect vulnerabilities via RPC: %w", err)
	}

	return r.ConvertFromRpcVulns(res.Vulnerabilities), nil
}
