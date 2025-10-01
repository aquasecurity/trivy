package cache

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

const (
	scanCacheDirName = "fanal"

	// artifactBucket stores artifact information with artifact ID such as image ID
	artifactBucket = "artifact"
	// blobBucket stores os, package and library information per blob ID such as layer ID
	blobBucket = "blob"
)

type Cache interface {
	ArtifactCache
	LocalArtifactCache
}

// ArtifactCache uses local or remote cache
type ArtifactCache interface {
	// MissingBlobs returns missing blob IDs such as layer IDs in cache
	MissingBlobs(ctx context.Context, artifactID string, blobIDs []string) (missingArtifact bool, missingBlobIDs []string, err error)

	// PutArtifact stores artifact information such as image metadata in cache
	PutArtifact(ctx context.Context, artifactID string, artifactInfo types.ArtifactInfo) (err error)

	// PutBlob stores blob information such as layer information in local cache
	PutBlob(ctx context.Context, blobID string, blobInfo types.BlobInfo) (err error)

	// DeleteBlobs removes blobs by IDs
	DeleteBlobs(ctx context.Context, blobIDs []string) error
}

// LocalArtifactCache always uses local cache
type LocalArtifactCache interface {
	// GetArtifact gets artifact information such as image metadata from local cache
	GetArtifact(ctx context.Context, artifactID string) (artifactInfo types.ArtifactInfo, err error)

	// GetBlob gets blob information such as layer data from local cache
	GetBlob(ctx context.Context, blobID string) (blobInfo types.BlobInfo, err error)

	// Close closes the local database
	Close() (err error)

	// Clear deletes the local database
	Clear(ctx context.Context) (err error)
}
