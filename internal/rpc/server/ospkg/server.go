package ospkg

import (
	"context"

	"github.com/aquasecurity/trivy/internal/rpc"

	"github.com/aquasecurity/trivy/pkg/vulnerability"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg"
	proto "github.com/aquasecurity/trivy/rpc/detector"
)

type Server struct{}

func (s *Server) Detect(ctx context.Context, req *proto.OSDetectRequest) (res *proto.DetectResponse, err error) {
	// remoteURL is already empty for server
	detector := ospkg.NewDetector(req.OsFamily, req.OsName, "", "")
	if detector == nil {
		// Unsupported OS
		return nil, nil
	}
	vulns, err := detector.Detect(req.OsFamily, req.OsName, rpc.ConvertFromRpcPkgs(req.Packages))
	if err != nil {
		log.Logger.Warn(err)
		return nil, err
	}

	vulnClient := vulnerability.NewClient()
	vulnClient.FillInfo(vulns, false)

	return &proto.DetectResponse{Vulnerabilities: rpc.ConvertToRpcVulns(vulns)}, nil
}
