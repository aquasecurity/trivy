package server

import (
	"context"

	"github.com/google/wire"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/log"
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
	NewScanServer,
)

// ScanServer implements the scanner
type ScanServer struct {
	localScanner scanner.Driver
}

// NewScanServer is the factory method for scanner
func NewScanServer(s scanner.Driver) *ScanServer {
	return &ScanServer{localScanner: s}
}

// Log and return an error
func teeError(err error) error {
	log.Errorf("%+v", err)
	return err
}

// Scan scans and return response
func (s *ScanServer) Scan(ctx context.Context, in *rpcScanner.ScanRequest) (*rpcScanner.ScanResponse, error) {
	scanners := lo.Map(in.Options.Scanners, func(s string, index int) types.Scanner {
		return types.Scanner(s)
	})
	options := types.ScanOptions{
		VulnType:       in.Options.VulnType,
		Scanners:       scanners,
		IncludeDevDeps: in.Options.IncludeDevDeps,
	}
	results, os, err := s.localScanner.Scan(ctx, in.Target, in.ArtifactId, in.BlobIds, options)
	if err != nil {
		return nil, teeError(xerrors.Errorf("failed scan, %s: %w", in.Target, err))
	}

	return rpc.ConvertToRPCScanResponse(results, os), nil
}

// CacheServer implements the cache
type CacheServer struct {
	cache cache.Cache
}

// NewCacheServer is the factory method for cacheServer
func NewCacheServer(c cache.Cache) *CacheServer {
	return &CacheServer{cache: c}
}

// PutArtifact puts the artifacts in cache
func (s *CacheServer) PutArtifact(_ context.Context, in *rpcCache.PutArtifactRequest) (*emptypb.Empty, error) {
	if in.ArtifactInfo == nil {
		return nil, teeError(xerrors.Errorf("empty image info"))
	}
	imageInfo := rpc.ConvertFromRPCPutArtifactRequest(in)
	if err := s.cache.PutArtifact(in.ArtifactId, imageInfo); err != nil {
		return nil, teeError(xerrors.Errorf("unable to store image info in cache: %w", err))
	}
	return &emptypb.Empty{}, nil
}

// PutBlob puts the blobs in cache
func (s *CacheServer) PutBlob(_ context.Context, in *rpcCache.PutBlobRequest) (*emptypb.Empty, error) {
	if in.BlobInfo == nil {
		return nil, teeError(xerrors.Errorf("empty layer info"))
	}
	layerInfo := rpc.ConvertFromRPCPutBlobRequest(in)
	if err := s.cache.PutBlob(in.DiffId, layerInfo); err != nil {
		return nil, teeError(xerrors.Errorf("unable to store layer info in cache: %w", err))
	}
	return &emptypb.Empty{}, nil
}

// MissingBlobs returns missing blobs from cache
func (s *CacheServer) MissingBlobs(_ context.Context, in *rpcCache.MissingBlobsRequest) (*rpcCache.MissingBlobsResponse, error) {
	missingArtifact, blobIDs, err := s.cache.MissingBlobs(in.ArtifactId, in.BlobIds)
	if err != nil {
		return nil, teeError(xerrors.Errorf("failed to get missing blobs: %w", err))
	}
	return &rpcCache.MissingBlobsResponse{
		MissingArtifact: missingArtifact,
		MissingBlobIds:  blobIDs,
	}, nil
}

// DeleteBlobs removes blobs by IDs
func (s *CacheServer) DeleteBlobs(_ context.Context, in *rpcCache.DeleteBlobsRequest) (*emptypb.Empty, error) {
	blobIDs := rpc.ConvertFromDeleteBlobsRequest(in)
	if err := s.cache.DeleteBlobs(blobIDs); err != nil {
		return nil, teeError(xerrors.Errorf("failed to remove a blobs: %w", err))
	}
	return &emptypb.Empty{}, nil
}
