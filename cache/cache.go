package cache

import (
	"github.com/aquasecurity/fanal/types"
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
	MissingBlobs(artifactID string, blobIDs []string, analyzerVersions, configAnalyzerVersions map[string]int) (
		missingArtifact bool, missingBlobIDs []string, err error)

	// PutArtifact stores artifact information such as image metadata in cache
	PutArtifact(artifactID string, artifactInfo types.ArtifactInfo) (err error)

	// PutBlob stores blob information such as layer information in local cache
	PutBlob(blobID string, blobInfo types.BlobInfo) (err error)
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

// isStale checks if the cache is stale or not.
// e.g. When {"alpine": 1, "python": 2} is cached and {"alpine": 2, "python": 2} is sent, the cache is stale.
// Also, {"python": 2} cache must be replaced by {"alpine": 1, "python": 2}.
func isStale(current, cached map[string]int) bool {
	for analyzerType, currentVersion := range current {
		cachedVersion, ok := cached[analyzerType]
		if !ok {
			return true
		}
		if cachedVersion < currentVersion {
			return true
		}
	}
	return false
}
