package cachetest

import (
	"context"
	"errors"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	GetArtifact  bool
	GetBlob      bool
}

func NewErrorCache(opts ErrorCacheOptions) *ErrorCache {
	return &ErrorCache{
		MemoryCache: cache.NewMemoryCache(),
		opts:        opts,
	}
}

func (c *ErrorCache) MissingBlobs(ctx context.Context, artifactID string, blobIDs []string) (bool, []string, error) {
	if c.opts.MissingBlobs {
		return false, nil, errors.New("MissingBlobs failed")
	}
	return c.MemoryCache.MissingBlobs(ctx, artifactID, blobIDs)
}

func (c *ErrorCache) PutArtifact(ctx context.Context, artifactID string, artifactInfo types.ArtifactInfo) error {
	if c.opts.PutArtifact {
		return errors.New("PutArtifact failed")
	}
	return c.MemoryCache.PutArtifact(ctx, artifactID, artifactInfo)
}

func (c *ErrorCache) PutBlob(ctx context.Context, artifactID string, blobInfo types.BlobInfo) error {
	if c.opts.PutBlob {
		return errors.New("PutBlob failed")
	}
	return c.MemoryCache.PutBlob(ctx, artifactID, blobInfo)
}

func (c *ErrorCache) GetArtifact(ctx context.Context, artifactID string) (types.ArtifactInfo, error) {
	if c.opts.GetArtifact {
		return types.ArtifactInfo{}, errors.New("GetArtifact failed")
	}
	return c.MemoryCache.GetArtifact(ctx, artifactID)
}

func (c *ErrorCache) GetBlob(ctx context.Context, blobID string) (types.BlobInfo, error) {
	if c.opts.GetBlob {
		return types.BlobInfo{}, errors.New("GetBlob failed")
	}
	return c.MemoryCache.GetBlob(ctx, blobID)
}

func NewCache(t *testing.T, setUpCache func(t *testing.T) cache.Cache) cache.Cache {
	if setUpCache != nil {
		return setUpCache(t)
	}
	return cache.NewMemoryCache()
}

func AssertArtifact(t *testing.T, c cache.Cache, wantArtifact WantArtifact) {
	gotArtifact, err := c.GetArtifact(t.Context(), wantArtifact.ID)
	require.NoError(t, err, "artifact not found")
	assert.Equal(t, wantArtifact.ArtifactInfo, gotArtifact, wantArtifact.ID)
}

func AssertBlobs(t *testing.T, c cache.Cache, wantBlobs []WantBlob) {
	if m, ok := c.(*cache.MemoryCache); ok {
		blobIDs := m.BlobIDs()
		wantBlobIDs := lo.Map(wantBlobs, func(want WantBlob, _ int) string {
			return want.ID
		})
		require.ElementsMatch(t, wantBlobIDs, blobIDs, "blob IDs mismatch")
	}

	for _, want := range wantBlobs {
		got, err := c.GetBlob(t.Context(), want.ID)
		require.NoError(t, err, "blob not found")

		for i := range got.Misconfigurations {
			// suppress misconfiguration code block
			for j := range got.Misconfigurations[i].Failures {
				got.Misconfigurations[i].Failures[j].Code = types.Code{}
			}
			for j := range got.Misconfigurations[i].Successes {
				got.Misconfigurations[i].Successes[j].Code = types.Code{}
			}
			for j := range got.Misconfigurations[i].Warnings {
				got.Misconfigurations[i].Warnings[j].Code = types.Code{}
			}
		}

		assert.Equal(t, want.BlobInfo, got, want.ID)
	}
}
