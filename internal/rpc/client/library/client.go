package library

import (
	"context"
	"net/http"

	"github.com/aquasecurity/trivy/internal/rpc/client"

	"github.com/aquasecurity/trivy/internal/rpc"
	"github.com/aquasecurity/trivy/pkg/types"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/rpc/detector"
	"golang.org/x/xerrors"
)

type DetectClient struct {
	token  string
	client detector.LibDetector
}

func NewDetectClient(remoteURL, token string) DetectClient {
	client := detector.NewLibDetectorProtobufClient(remoteURL, &http.Client{})
	return DetectClient{token: token, client: client}
}

func (d DetectClient) Detect(filePath string, libs []ptypes.Library) ([]types.DetectedVulnerability, error) {
	res, err := d.client.Detect(client.WithToken(context.Background(), d.token), &detector.LibDetectRequest{
		FilePath:  filePath,
		Libraries: rpc.ConvertToRpcLibraries(libs),
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to detect vulnerabilities via RPC: %w", err)
	}

	return rpc.ConvertFromRpcVulns(res.Vulnerabilities), nil
}
