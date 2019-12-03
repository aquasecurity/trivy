package library

import (
	"context"

	"github.com/aquasecurity/trivy/internal/rpc"

	"github.com/aquasecurity/trivy/pkg/vulnerability"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/library"
	proto "github.com/aquasecurity/trivy/rpc/detector"
)

type Server struct{}

func (s *Server) Detect(ctx context.Context, req *proto.LibDetectRequest) (res *proto.DetectResponse, err error) {
	// remoteURL and token are already empty for server
	detector := library.NewDetector("", "")
	vulns, err := detector.Detect(req.FilePath, rpc.ConvertFromRpcLibraries(req.Libraries))
	if err != nil {
		log.Logger.Warn(err)
		return nil, err
	}

	vulnClient := vulnerability.NewClient()
	vulnClient.FillInfo(vulns, false)

	return &proto.DetectResponse{Vulnerabilities: rpc.ConvertToRpcVulns(vulns)}, nil
}
