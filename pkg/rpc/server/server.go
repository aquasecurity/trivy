package server

import (
	"context"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/google/wire"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	rpcCache "github.com/aquasecurity/trivy/rpc/cache"
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
	results, os, eosl, err := s.localScanner.Scan(in.Target, in.ImageId, in.LayerIds, options)
	if err != nil {
		return nil, xerrors.Errorf("failed scan, %s: %w", in.Target, err)
	}

	for i := range results {
		s.vulnClient.FillInfo(results[i].Vulnerabilities, false)
	}
	return rpc.ConvertToRpcScanResponse(results, os, eosl), nil
}

type CacheServer struct {
	cache cache.Cache
}

func NewCacheServer(c cache.Cache) *CacheServer {
	return &CacheServer{cache: c}
}

func (s *CacheServer) PutImage(_ context.Context, in *rpcCache.PutImageRequest) (*google_protobuf.Empty, error) {
	if in.ImageInfo == nil {
		return nil, xerrors.Errorf("empty image info")
	}
	imageInfo := rpc.ConvertFromRpcPutImageRequest(in)
	if err := s.cache.PutImage(in.ImageId, imageInfo); err != nil {
		return nil, xerrors.Errorf("unable to store image info in cache: %w", err)
	}
	return &google_protobuf.Empty{}, nil
}

func (s *CacheServer) PutLayer(_ context.Context, in *rpcCache.PutLayerRequest) (*google_protobuf.Empty, error) {
	if in.LayerInfo == nil {
		return nil, xerrors.Errorf("empty layer info")
	}
	layerInfo := rpc.ConvertFromRpcPutLayerRequest(in)
	if err := s.cache.PutLayer(in.DiffId, layerInfo); err != nil {
		return nil, xerrors.Errorf("unable to store layer info in cache: %w", err)
	}
	return &google_protobuf.Empty{}, nil
}

func (s *CacheServer) MissingLayers(_ context.Context, in *rpcCache.MissingLayersRequest) (*rpcCache.MissingLayersResponse, error) {
	var layerIDs []string
	for _, layerID := range in.LayerIds {
		l, err := s.cache.GetLayer(layerID)
		if err != nil || l.SchemaVersion != ftypes.LayerJSONSchemaVersion {
			layerIDs = append(layerIDs, layerID)
		}
	}
	var missingImage bool
	img, err := s.cache.GetImage(in.ImageId)
	if err != nil || img.SchemaVersion != ftypes.ImageJSONSchemaVersion {
		missingImage = true
	}
	return &rpcCache.MissingLayersResponse{MissingImage: missingImage, MissingLayerIds: layerIDs}, nil
}
