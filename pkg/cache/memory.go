package cache

import (
	"context"
	"sync"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

var _ Cache = &MemoryCache{}

type MemoryCache struct {
	artifacts sync.Map // Map to store artifact information
	blobs     sync.Map // Map to store blob information
}

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{}
}

// PutArtifact stores the artifact information in the memory cache
func (c *MemoryCache) PutArtifact(_ context.Context, artifactID string, artifactInfo types.ArtifactInfo) error {
	c.artifacts.Store(artifactID, artifactInfo)
	return nil
}

// PutBlob stores the blob information in the memory cache
func (c *MemoryCache) PutBlob(_ context.Context, blobID string, blobInfo types.BlobInfo) error {
	c.blobs.Store(blobID, blobInfo)
	return nil
}

// DeleteBlobs removes the specified blobs from the memory cache
func (c *MemoryCache) DeleteBlobs(_ context.Context, blobIDs []string) error {
	for _, blobID := range blobIDs {
		c.blobs.Delete(blobID)
	}
	return nil
}

// GetArtifact retrieves the artifact information from the memory cache
func (c *MemoryCache) GetArtifact(_ context.Context, artifactID string) (types.ArtifactInfo, error) {
	info, ok := c.artifacts.Load(artifactID)
	if !ok {
		return types.ArtifactInfo{}, xerrors.Errorf("artifact (%s) not found in memory cache", artifactID)
	}
	artifactInfo, ok := info.(types.ArtifactInfo)
	if !ok {
		return types.ArtifactInfo{}, xerrors.Errorf("invalid type for artifact (%s) in memory cache", artifactID)
	}
	return artifactInfo, nil
}

// GetBlob retrieves the blob information from the memory cache
func (c *MemoryCache) GetBlob(_ context.Context, blobID string) (types.BlobInfo, error) {
	info, ok := c.blobs.Load(blobID)
	if !ok {
		return types.BlobInfo{}, xerrors.Errorf("blob (%s) not found in memory cache", blobID)
	}
	blobInfo, ok := info.(types.BlobInfo)
	if !ok {
		return types.BlobInfo{}, xerrors.Errorf("invalid type for blob (%s) in memory cache", blobID)
	}
	return blobInfo, nil
}

// MissingBlobs determines the missing artifact and blob information in the memory cache
func (c *MemoryCache) MissingBlobs(ctx context.Context, artifactID string, blobIDs []string) (bool, []string, error) {
	var missingArtifact bool
	var missingBlobIDs []string

	if _, err := c.GetArtifact(ctx, artifactID); err != nil {
		missingArtifact = true
	}

	for _, blobID := range blobIDs {
		if _, err := c.GetBlob(ctx, blobID); err != nil {
			missingBlobIDs = append(missingBlobIDs, blobID)
		}
	}

	return missingArtifact, missingBlobIDs, nil
}

// Close clears the artifact and blob information from the memory cache
func (c *MemoryCache) Close() error {
	c.artifacts = sync.Map{}
	c.blobs = sync.Map{}
	return nil
}

// Clear clears the artifact and blob information from the memory cache
func (c *MemoryCache) Clear(_ context.Context) error {
	c.artifacts = sync.Map{}
	c.blobs = sync.Map{}
	return nil
}

// BlobIDs returns all the blob IDs in the memory cache for testing
func (c *MemoryCache) BlobIDs() []string {
	var blobIDs []string
	c.blobs.Range(func(key, _ any) bool {
		blobID, ok := key.(string)
		if !ok {
			return false
		}
		blobIDs = append(blobIDs, blobID)
		return true
	})
	return blobIDs
}
