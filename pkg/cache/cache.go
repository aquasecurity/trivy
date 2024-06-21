package cache

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

const (
	cacheDirName = "fanal"

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
	MissingBlobs(artifactID string, blobIDs []string) (missingArtifact bool, missingBlobIDs []string, err error)

	// PutArtifact stores artifact information such as image metadata in cache
	PutArtifact(artifactID string, artifactInfo types.ArtifactInfo) (err error)

	// PutBlob stores blob information such as layer information in local cache
	PutBlob(blobID string, blobInfo types.BlobInfo) (err error)

	// DeleteBlobs removes blobs by IDs
	DeleteBlobs(blobIDs []string) error
}

// LocalArtifactCache always uses local cache
type LocalArtifactCache interface {
	// GetArtifact gets artifact information such as image metadata from local cache
	GetArtifact(artifactID string) (artifactInfo types.ArtifactInfo, err error)

	// GetBlob gets blob information such as layer data from local cache
	GetBlob(blobID string) (blobInfo types.BlobInfo, err error)

	// Close closes the local database
	Close() (err error)

	// Clear deletes the local database
	Clear() (err error)
}
