package library

import (
	"context"
	"net/http"

	"github.com/google/wire"

	"github.com/aquasecurity/trivy/internal/rpc/client"

	"github.com/aquasecurity/trivy/internal/rpc"
	"github.com/aquasecurity/trivy/pkg/types"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/rpc/detector"
	"golang.org/x/xerrors"
)

var SuperSet = wire.NewSet(
	&http.Client{},
	NewProtobufClient,
	NewDetector,
)

type RemoteURL string

func NewProtobufClient(remoteURL RemoteURL, client *http.Client) detector.LibDetector {
	return detector.NewLibDetectorProtobufClient(string(remoteURL), client)
}

type Token string

type Detector struct {
	token  Token
	client detector.LibDetector
}

func NewDetector(token Token, detector detector.LibDetector) Detector {
	return Detector{token: token, client: detector}
}

func (d Detector) Detect(filePath string, libs []ptypes.Library) ([]types.DetectedVulnerability, error) {
	ctx := client.WithToken(context.Background(), string(d.token))
	res, err := d.client.Detect(ctx, &detector.LibDetectRequest{
		FilePath:  filePath,
		Libraries: rpc.ConvertToRpcLibraries(libs),
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to detect vulnerabilities via RPC: %w", err)
	}

	return rpc.ConvertFromRpcVulns(res.Vulnerabilities), nil
}
