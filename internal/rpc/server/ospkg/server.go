package ospkg

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/internal/rpc"

	"github.com/aquasecurity/trivy/pkg/vulnerability"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg"
	proto "github.com/aquasecurity/trivy/rpc/detector"
)

type Server struct {
	newDetector func(string, string, string, string) ospkg.DetectorOperation
	vulnClient  vulnerability.Operation
}

func NewServer() Server {
	vulnClient := vulnerability.NewClient()
	return Server{
		newDetector: ospkg.NewDetector,
		vulnClient:  vulnClient,
	}
}

func (s *Server) Detect(ctx context.Context, req *proto.OSDetectRequest) (res *proto.DetectResponse, err error) {
	// remoteURL is already empty for server
	detector := s.newDetector(req.OsFamily, req.OsName, "", "")
	if detector == nil {
		// Unsupported OS
		return nil, nil
	}
	vulns, err := detector.Detect(req.OsFamily, req.OsName, rpc.ConvertFromRpcPkgs(req.Packages))
	if err != nil {
		log.Logger.Warn(err)
		return nil, xerrors.Errorf("failed to detect vulnerabilities")
	}

	s.vulnClient.FillInfo(vulns, false)

	return &proto.DetectResponse{Vulnerabilities: rpc.ConvertToRpcVulns(vulns)}, nil
}
