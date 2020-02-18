package server

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/scanner"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/types"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/google/wire"
	digest "github.com/opencontainers/go-digest"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	rpcLayer "github.com/aquasecurity/trivy/rpc/layer"
	rpcScanner "github.com/aquasecurity/trivy/rpc/scanner"
)

var ScanSuperSet = wire.NewSet(
	local.SuperSet,
	wire.Bind(new(scanner.Driver), new(local.Scanner)),
	vulnerability.SuperSet,
	NewScanServer,
)

type ScanServer struct {
	localScanner scanner.Driver
	vulnClient   vulnerability.Operation
}

func NewScanServer(s scanner.Driver, vulnClient vulnerability.Operation) *ScanServer {
	return &ScanServer{localScanner: s, vulnClient: vulnClient}
}

func (s *ScanServer) Scan(_ context.Context, in *rpcScanner.ScanRequest) (*rpcScanner.ScanResponse, error) {
	options := types.ScanOptions{VulnType: in.Options.VulnType}
	results, os, eosl, err := s.localScanner.Scan(in.Target, digest.Digest(in.ImageId), in.LayerIds, options)
	if err != nil {
		return nil, xerrors.Errorf("failed scan, %s: %w", in.Target, err)
	}

	for i := range results {
		s.vulnClient.FillInfo(results[i].Vulnerabilities, false)
	}
	return rpc.ConvertToRpcScanResponse(results, os, eosl), nil
}

type LayerServer struct {
	cache cache.Cache
}

func NewLayerServer(c cache.Cache) *LayerServer {
	return &LayerServer{cache: c}
}

func (s *LayerServer) Put(_ context.Context, in *rpcLayer.PutRequest) (*google_protobuf.Empty, error) {
	layerInfo := rpc.ConvertFromRpcPutRequest(in)
	if err := s.cache.PutLayer(in.LayerId, in.DecompressedLayerId, layerInfo); err != nil {
		return nil, xerrors.Errorf("unable to store layer info in cache: %w", err)
	}
	return &google_protobuf.Empty{}, nil
}

func (s *LayerServer) MissingLayers(_ context.Context, in *rpcLayer.Layers) (*rpcLayer.Layers, error) {
	var layerIDs []string
	for _, layerID := range in.LayerIds {
		b := s.cache.GetLayer(layerID)
		if b == nil {
			layerIDs = append(layerIDs, layerID)
		}
	}
	return &rpcLayer.Layers{LayerIds: layerIDs}, nil
}
