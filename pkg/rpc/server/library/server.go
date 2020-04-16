package library

import (
	"context"
	"time"

	"github.com/google/wire"
	"golang.org/x/xerrors"

	detector "github.com/aquasecurity/trivy/pkg/detector/library"
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
func (s *Server) Detect(_ context.Context, req *proto.LibDetectRequest) (res *proto.DetectResponse, err error) {
	vulns, err := s.detector.Detect("", req.FilePath, time.Time{}, rpc.ConvertFromRpcLibraries(req.Libraries))
	if err != nil {
		err = xerrors.Errorf("failed to detect library vulnerabilities: %w", err)
		log.Logger.Error(err)
		return nil, err
	}

	s.vulnClient.FillInfo(vulns, "")

	return &proto.DetectResponse{Vulnerabilities: rpc.ConvertToRpcVulns(vulns)}, nil
}
