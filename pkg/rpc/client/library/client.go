package library

import (
	"context"
	"net/http"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/google/wire"
	"github.com/twitchtv/twirp"
	"golang.org/x/xerrors"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	detector "github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/log"
	r "github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/types"
	rpc "github.com/aquasecurity/trivy/rpc/detector"
)

const (
	maxRetries = 10
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

	var res *rpc.DetectResponse
	operation := func() error {
		var err error
		res, err = d.client.Detect(ctx, &rpc.LibDetectRequest{
			FilePath:  filePath,
			Libraries: r.ConvertToRpcLibraries(libs),
		})
		if err != nil {
			twerr, ok := err.(twirp.Error)
			if !ok {
				return backoff.Permanent(err)
			}
			if twerr.Code() == twirp.Unavailable {
				return err
			}
			return backoff.Permanent(err)
		}
		return nil
	}

	b := backoff.WithMaxRetries(backoff.NewExponentialBackOff(), maxRetries)
	err := backoff.RetryNotify(operation, b, func(err error, _ time.Duration) {
		log.Logger.Warn(err)
		log.Logger.Info("Retrying HTTP request...")
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to detect vulnerabilities via RPC: %w", err)
	}

	return r.ConvertFromRpcVulns(res.Vulnerabilities), nil
}
