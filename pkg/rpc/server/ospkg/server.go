package ospkg

import (
	"context"
	"time"

	"github.com/google/wire"
	"golang.org/x/xerrors"

	detector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	proto "github.com/aquasecurity/trivy/rpc/detector"
)

var SuperSet = wire.NewSet(
	detector.SuperSet,
	vulnerability.SuperSet,
	NewServer,
)

// Server is for backward compatibility
type Server struct {
	detector   detector.Operation
	vulnClient vulnerability.Operation
}

func NewServer(detector detector.Operation, vulnClient vulnerability.Operation) *Server {
	return &Server{detector: detector, vulnClient: vulnClient}
}

// Detect is for backward compatibility
func (s *Server) Detect(_ context.Context, req *proto.OSDetectRequest) (res *proto.DetectResponse, err error) {
	vulns, eosl, err := s.detector.Detect("", req.OsFamily, req.OsName, time.Time{}, rpc.ConvertFromRpcPkgs(req.Packages))
	if err != nil {
		err = xerrors.Errorf("failed to detect vulnerabilities of OS packages: %w", err)
		log.Logger.Error(err)
		return nil, err
	}

	s.vulnClient.FillInfo(vulns, "")

	return &proto.DetectResponse{Vulnerabilities: rpc.ConvertToRpcVulns(vulns), Eosl: eosl}, nil
}
