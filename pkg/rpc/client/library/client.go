package library

import (
	"context"
	"net/http"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/google/wire"
	"golang.org/x/xerrors"

	depptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	detector "github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/log"
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

func (d Detector) Detect(imageName, filePath string, created time.Time, libs []depptypes.Library) ([]types.DetectedVulnerability, error) {
	ctx := client.WithCustomHeaders(context.Background(), http.Header(d.customHeaders))

	var res *rpc.DetectResponse
	err := r.Retry(func() error {
		var err error
		res, err = d.client.Detect(ctx, &rpc.LibDetectRequest{
			ImageName: imageName,
			FilePath:  filePath,
			Libraries: r.ConvertToRpcLibraries(libs),
			Created: func() *timestamp.Timestamp {
				t, err := ptypes.TimestampProto(created)
				if err != nil {
					log.Logger.Warnf("invalid timestamp: %s", err)
				}
				return t
			}(),
		})
		return err
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to detect vulnerabilities via RPC: %w", err)
	}

	return r.ConvertFromRpcVulns(res.Vulnerabilities), nil
}
