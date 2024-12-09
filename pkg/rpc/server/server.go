package server

import (
	"context"

	"github.com/google/wire"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/aquasecurity/trivy/pkg/cache"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
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
	options := s.ToOptions(in.Options)
	results, os, err := s.localScanner.Scan(ctx, in.Target, in.ArtifactId, in.BlobIds, options)
	if err != nil {
		return nil, teeError(xerrors.Errorf("failed scan, %s: %w", in.Target, err))
	}

	return rpc.ConvertToRPCScanResponse(results, os), nil
}

func (s *ScanServer) ToOptions(in *rpcScanner.ScanOptions) types.ScanOptions {
	pkgRelationships := lo.FilterMap(in.PkgRelationships, func(r string, index int) (ftypes.Relationship, bool) {
		rel, err := ftypes.NewRelationship(r)
		if err != nil {
			log.Warnf("Invalid relationship: %s", r)
			return ftypes.RelationshipUnknown, false
		}
		return rel, true
	})
	if len(pkgRelationships) == 0 {
		pkgRelationships = ftypes.Relationships // For backward compatibility
	}

	scanners := lo.Map(in.Scanners, func(s string, index int) types.Scanner {
		return types.Scanner(s)
	})

	licenseCategories := lo.MapEntries(in.LicenseCategories,
		func(k string, v *rpcScanner.Licenses) (ftypes.LicenseCategory, []string) {
			return ftypes.LicenseCategory(k), v.Names
		})

	var distro ftypes.OS
	if in.Distro != nil {
		distro.Family = ftypes.OSType(in.Distro.Family)
		distro.Name = in.Distro.Name
	}

	return types.ScanOptions{
		PkgTypes:          in.PkgTypes,
		PkgRelationships:  pkgRelationships,
		Scanners:          scanners,
		IncludeDevDeps:    in.IncludeDevDeps,
		LicenseCategories: licenseCategories,
		Distro:            distro,
	}
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
