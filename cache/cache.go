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

type options struct {
	S3Prefix string
}

type Option interface {
	Apply(opts *options)
}

type S3Prefix string

func (o S3Prefix) Apply(g *options) {
	g.S3Prefix = string(o)
}

type Cache interface {
	ArtifactCache
	LocalArtifactCache
}

func initOpts(opts []Option) *options {
	options := new(options)
	for _, opt := range opts {
		opt.Apply(options)
	}
	return options
}

// ArtifactCache uses local or remote cache
type ArtifactCache interface {
	// MissingBlobs returns missing blob IDs such as layer IDs in cache
	MissingBlobs(artifactID string, blobIDs []string, opts ...Option) (missingArtifact bool, missingBlobIDs []string, err error)

	// PutArtifact stores artifact information such as image metadata in cache
	PutArtifact(artifactID string, artifactInfo types.ArtifactInfo, opts ...Option) (err error)

	// PutBlob stores blob information such as layer information in local cache
	PutBlob(blobID string, blobInfo types.BlobInfo, opts ...Option) (err error)
}

// LocalArtifactCache always uses local cache
type LocalArtifactCache interface {
	// GetArtifact gets artifact information such as image metadata from local cache
	GetArtifact(artifactID string, opts ...Option) (artifactInfo types.ArtifactInfo, err error)

	// GetBlob gets blob information such as layer data from local cache
	GetBlob(blobID string, opts ...Option) (blobInfo types.BlobInfo, err error)

	// Close closes the local database
	Close() (err error)

	// Clear deletes the local database
	Clear() (err error)
}
