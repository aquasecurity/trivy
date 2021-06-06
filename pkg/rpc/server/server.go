package server

import (
	"context"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/google/wire"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/types"
	rpcCache "github.com/aquasecurity/trivy/rpc/cache"
	rpcScanner "github.com/aquasecurity/trivy/rpc/scanner"
)

// ScanSuperSet binds the dependencies for server
var ScanSuperSet = wire.NewSet(
	local.SuperSet,
	wire.Bind(new(scanner.Driver), new(local.Scanner)),
	result.SuperSet,
	NewScanServer,
)

// ScanServer implements the scanner
type ScanServer struct {
	localScanner scanner.Driver
	resultClient result.Client
}

// NewScanServer is the factory method for scanner
func NewScanServer(s scanner.Driver, vulnClient result.Client) *ScanServer {
	return &ScanServer{localScanner: s, resultClient: vulnClient}
}

// Scan scans and return response
func (s *ScanServer) Scan(_ context.Context, in *rpcScanner.ScanRequest) (*rpcScanner.ScanResponse, error) {
	options := types.ScanOptions{
		VulnType:        in.Options.VulnType,
		SecurityChecks:  in.Options.SecurityChecks,
		ListAllPackages: in.Options.ListAllPackages,
	}
	results, os, eosl, err := s.localScanner.Scan(in.Target, in.ArtifactId, in.BlobIds, options)
	if err != nil {
		return nil, xerrors.Errorf("failed scan, %s: %w", in.Target, err)
	}

	for i := range results {
		s.resultClient.FillVulnerabilityInfo(results[i].Vulnerabilities, results[i].Type)
	}
	return rpc.ConvertToRPCScanResponse(results, os, eosl), nil
}

// CacheServer implements the cache
type CacheServer struct {
	cache cache.Cache
}

// NewCacheServer is the facotry method for cacheServer
func NewCacheServer(c cache.Cache) *CacheServer {
	return &CacheServer{cache: c}
}

// PutArtifact puts the artifacts in cache
func (s *CacheServer) PutArtifact(_ context.Context, in *rpcCache.PutArtifactRequest) (*google_protobuf.Empty, error) {
	if in.ArtifactInfo == nil {
		return nil, xerrors.Errorf("empty image info")
	}
	imageInfo := rpc.ConvertFromRPCPutArtifactRequest(in)
	if err := s.cache.PutArtifact(in.ArtifactId, imageInfo); err != nil {
		return nil, xerrors.Errorf("unable to store image info in cache: %w", err)
	}
	return &google_protobuf.Empty{}, nil
}

// PutBlob puts the blobs in cache
func (s *CacheServer) PutBlob(_ context.Context, in *rpcCache.PutBlobRequest) (*google_protobuf.Empty, error) {
	if in.BlobInfo == nil {
		return nil, xerrors.Errorf("empty layer info")
	}
	layerInfo := rpc.ConvertFromRPCPutBlobRequest(in)
	if err := s.cache.PutBlob(in.DiffId, layerInfo); err != nil {
		return nil, xerrors.Errorf("unable to store layer info in cache: %w", err)
	}
	return &google_protobuf.Empty{}, nil
}

// MissingBlobs returns missing blobs from cache
func (s *CacheServer) MissingBlobs(_ context.Context, in *rpcCache.MissingBlobsRequest) (*rpcCache.MissingBlobsResponse, error) {
	missingArtifact, blobIDs, err := s.cache.MissingBlobs(in.ArtifactId, in.BlobIds)
	if err != nil {
		return nil, xerrors.Errorf("failed to get missing blobs: %w", err)
	}
	return &rpcCache.MissingBlobsResponse{MissingArtifact: missingArtifact, MissingBlobIds: blobIDs}, nil
}
