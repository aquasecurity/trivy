package ospkg

import (
	"context"
	"net/http"
	"time"

	"github.com/aquasecurity/trivy/pkg/log"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"

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

func (d Detector) Detect(imageName, osFamily, osName string, created time.Time, pkgs []analyzer.Package) ([]types.DetectedVulnerability, bool, error) {
	ctx := client.WithCustomHeaders(context.Background(), http.Header(d.customHeaders))

	var res *rpc.DetectResponse
	err := r.Retry(func() error {
		var err error
		res, err = d.client.Detect(ctx, &rpc.OSDetectRequest{
			ImageName: imageName,
			OsFamily:  osFamily,
			OsName:    osName,
			Created: func() *timestamp.Timestamp {
				t, err := ptypes.TimestampProto(created)
				if err != nil {
					log.Logger.Warnf("invalid timestamp: %s", err)
				}
				return t
			}(),
			Packages: r.ConvertToRpcPkgs(pkgs),
		})
		return err
	})
	if err != nil {
		return nil, false, xerrors.Errorf("failed to detect vulnerabilities via RPC: %w", err)
	}

	return r.ConvertFromRpcVulns(res.Vulnerabilities), res.Eosl, nil
}
