package library

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/internal/rpc"

	"github.com/aquasecurity/trivy/pkg/vulnerability"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/library"
	proto "github.com/aquasecurity/trivy/rpc/detector"
)

type Server struct {
	detector   library.DetectorOperation
	vulnClient vulnerability.Operation
}

func NewServer() Server {
	// remoteURL and token are already empty for server
	detector := library.NewDetector("", "")
	vulnClient := vulnerability.NewClient()
	return Server{detector: detector, vulnClient: vulnClient}
}

func (s *Server) Detect(ctx context.Context, req *proto.LibDetectRequest) (res *proto.DetectResponse, err error) {
	vulns, err := s.detector.Detect(req.FilePath, rpc.ConvertFromRpcLibraries(req.Libraries))
	if err != nil {
		log.Logger.Warn(err)
		return nil, xerrors.Errorf("failed to detect library vulnerabilities: %w", err)
	}

	s.vulnClient.FillInfo(vulns, false)

	return &proto.DetectResponse{Vulnerabilities: rpc.ConvertToRpcVulns(vulns)}, nil
}
