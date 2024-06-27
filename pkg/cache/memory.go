package cache

import (
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
func (c *MemoryCache) PutArtifact(artifactID string, artifactInfo types.ArtifactInfo) error {
	c.artifacts.Store(artifactID, artifactInfo)
	return nil
}

// PutBlob stores the blob information in the memory cache
func (c *MemoryCache) PutBlob(blobID string, blobInfo types.BlobInfo) error {
	c.blobs.Store(blobID, blobInfo)
	return nil
}

// DeleteBlobs removes the specified blobs from the memory cache
func (c *MemoryCache) DeleteBlobs(blobIDs []string) error {
	for _, blobID := range blobIDs {
		c.blobs.Delete(blobID)
	}
	return nil
}

// GetArtifact retrieves the artifact information from the memory cache
func (c *MemoryCache) GetArtifact(artifactID string) (types.ArtifactInfo, error) {
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
func (c *MemoryCache) GetBlob(blobID string) (types.BlobInfo, error) {
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
func (c *MemoryCache) MissingBlobs(artifactID string, blobIDs []string) (bool, []string, error) {
	var missingArtifact bool
	var missingBlobIDs []string

	if _, err := c.GetArtifact(artifactID); err != nil {
		missingArtifact = true
	}

	for _, blobID := range blobIDs {
		if _, err := c.GetBlob(blobID); err != nil {
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
func (c *MemoryCache) Clear() error {
	c.artifacts = sync.Map{}
	c.blobs = sync.Map{}
	return nil
}
