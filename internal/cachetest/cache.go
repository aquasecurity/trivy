package cachetest

import (
	"errors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type WantArtifact struct {
	ID           string
	ArtifactInfo types.ArtifactInfo
}

type WantBlob struct {
	ID       string
	BlobInfo types.BlobInfo
}

type ErrorCache struct {
	*cache.MemoryCache
	opts ErrorCacheOptions
}

type ErrorCacheOptions struct {
	MissingBlobs bool
	PutArtifact  bool
	PutBlob      bool
}

func NewErrorCache(c *cache.MemoryCache, opts ErrorCacheOptions) *ErrorCache {
	return &ErrorCache{
		MemoryCache: c,
		opts:        opts,
	}
}

func (c *ErrorCache) MissingBlobs(artifactID string, blobIDs []string) (bool, []string, error) {
	if c.opts.MissingBlobs {
		return false, nil, errors.New("MissingBlobs failed")
	}
	return c.MemoryCache.MissingBlobs(artifactID, blobIDs)
}

func (c *ErrorCache) PutArtifact(artifactID string, artifactInfo types.ArtifactInfo) error {
	if c.opts.PutArtifact {
		return errors.New("PutArtifact failed")
	}
	return c.MemoryCache.PutArtifact(artifactID, artifactInfo)
}

func (c *ErrorCache) PutBlob(artifactID string, blobInfo types.BlobInfo) error {
	if c.opts.PutBlob {
		return errors.New("PutBlob failed")
	}
	return c.MemoryCache.PutBlob(artifactID, blobInfo)
}
