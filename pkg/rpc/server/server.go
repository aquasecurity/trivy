package server

import (
	"context"

	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	"github.com/aquasecurity/trivy/pkg/scan/local"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
	rpcCache "github.com/aquasecurity/trivy/rpc/cache"
	rpcScanner "github.com/aquasecurity/trivy/rpc/scanner"
)

// ScanServer implements the scanner service.
// It uses local.Service as its backend to perform various types of security scanning.
type ScanServer struct {
	local scan.Backend
}

// NewScanServer creates a new ScanServer instance with the specified backend implementation.
func NewScanServer(s scan.Backend) *ScanServer {
	return &ScanServer{local: s}
}

// initializeScanServer creates a new RPC scan server with the provided cache.
func initializeScanServer(localArtifactCache cache.LocalArtifactCache) *ScanServer {
	applier := applier.NewApplier(localArtifactCache)
	osScanner := ospkg.NewScanner()
	langScanner := langpkg.NewScanner()
	vulnClient := vulnerability.NewClient(db.Config{})

	localService := local.NewService(applier, osScanner, langScanner, vulnClient)
	return NewScanServer(localService)
}

// Log and return an error
func teeError(err error) error {
	log.Errorf("%+v", err)
	return err
}

// Scan scans and return response
func (s *ScanServer) Scan(ctx context.Context, in *rpcScanner.ScanRequest) (*rpcScanner.ScanResponse, error) {
	options := s.ToOptions(in.Options)
	scanResponse, err := s.local.Scan(ctx, in.Target, in.ArtifactId, in.BlobIds, options)
	if err != nil {
		return nil, teeError(xerrors.Errorf("failed scan, %s: %w", in.Target, err))
	}

	return rpc.ConvertToRPCScanResponse(scanResponse), nil
}

func (s *ScanServer) ToOptions(in *rpcScanner.ScanOptions) types.ScanOptions {
	pkgRelationships := lo.FilterMap(in.PkgRelationships, func(r string, _ int) (ftypes.Relationship, bool) {
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

	scanners := lo.Map(in.Scanners, func(s string, _ int) types.Scanner {
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

	vulnSeveritySources := xstrings.ToTSlice[dbTypes.SourceID](in.VulnSeveritySources)
	if len(vulnSeveritySources) == 0 {
		vulnSeveritySources = []dbTypes.SourceID{
			"auto", // For backward compatibility
		}
	}

	return types.ScanOptions{
		PkgTypes:            in.PkgTypes,
		PkgRelationships:    pkgRelationships,
		Scanners:            scanners,
		IncludeDevDeps:      in.IncludeDevDeps,
		LicenseCategories:   licenseCategories,
		LicenseFull:         in.LicenseFull,
		Distro:              distro,
		VulnSeveritySources: vulnSeveritySources,
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
func (s *CacheServer) PutArtifact(ctx context.Context, in *rpcCache.PutArtifactRequest) (*emptypb.Empty, error) {
	if in.ArtifactInfo == nil {
		return nil, teeError(xerrors.Errorf("empty image info"))
	}
	imageInfo := rpc.ConvertFromRPCPutArtifactRequest(in)
	if err := s.cache.PutArtifact(ctx, in.ArtifactId, imageInfo); err != nil {
		return nil, teeError(xerrors.Errorf("unable to store image info in cache: %w", err))
	}
	return &emptypb.Empty{}, nil
}

// PutBlob puts the blobs in cache
func (s *CacheServer) PutBlob(ctx context.Context, in *rpcCache.PutBlobRequest) (*emptypb.Empty, error) {
	if in.BlobInfo == nil {
		return nil, teeError(xerrors.Errorf("empty layer info"))
	}
	layerInfo := rpc.ConvertFromRPCPutBlobRequest(in)
	if err := s.cache.PutBlob(ctx, in.DiffId, layerInfo); err != nil {
		return nil, teeError(xerrors.Errorf("unable to store layer info in cache: %w", err))
	}
	return &emptypb.Empty{}, nil
}

// MissingBlobs returns missing blobs from cache
func (s *CacheServer) MissingBlobs(ctx context.Context, in *rpcCache.MissingBlobsRequest) (*rpcCache.MissingBlobsResponse, error) {
	missingArtifact, blobIDs, err := s.cache.MissingBlobs(ctx, in.ArtifactId, in.BlobIds)

	if err != nil {
		return nil, teeError(xerrors.Errorf("failed to get missing blobs: %w", err))
	}
	return &rpcCache.MissingBlobsResponse{
		MissingArtifact: missingArtifact,
		MissingBlobIds:  blobIDs,
	}, nil
}

// DeleteBlobs removes blobs by IDs
func (s *CacheServer) DeleteBlobs(ctx context.Context, in *rpcCache.DeleteBlobsRequest) (*emptypb.Empty, error) {
	blobIDs := rpc.ConvertFromDeleteBlobsRequest(in)
	if err := s.cache.DeleteBlobs(ctx, blobIDs); err != nil {
		return nil, teeError(xerrors.Errorf("failed to remove a blobs: %w", err))
	}
	return &emptypb.Empty{}, nil
}
