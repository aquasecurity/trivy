package cache

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-multierror"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

var _ Cache = &FSCache{}

type FSCache struct {
	db        *bolt.DB
	directory string
}

func NewFSCache(cacheDir string) (FSCache, error) {
	dir := filepath.Join(cacheDir, cacheDirName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return FSCache{}, xerrors.Errorf("failed to create cache dir: %w", err)
	}

	db, err := bolt.Open(filepath.Join(dir, "fanal.db"), 0600, nil)
	if err != nil {
		return FSCache{}, xerrors.Errorf("unable to open DB: %w", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range []string{artifactBucket, blobBucket} {
			if _, err := tx.CreateBucketIfNotExists([]byte(bucket)); err != nil {
				return xerrors.Errorf("unable to create %s bucket: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return FSCache{}, xerrors.Errorf("DB error: %w", err)
	}

	return FSCache{
		db:        db,
		directory: dir,
	}, nil
}

// GetBlob gets blob information such as layer data from local cache
func (fs FSCache) GetBlob(blobID string) (types.BlobInfo, error) {
	var blobInfo types.BlobInfo
	err := fs.db.View(func(tx *bolt.Tx) error {
		var err error
		blobBucket := tx.Bucket([]byte(blobBucket))
		blobInfo, err = fs.getBlob(blobBucket, blobID)
		if err != nil {
			return xerrors.Errorf("failed to get blob from the cache: %w", err)
		}
		return nil
	})
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("DB error: %w", err)
	}
	return blobInfo, nil
}

func (fs FSCache) getBlob(blobBucket *bolt.Bucket, diffID string) (types.BlobInfo, error) {
	b := blobBucket.Get([]byte(diffID))

	var l types.BlobInfo
	if err := json.Unmarshal(b, &l); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("JSON unmarshal error: %w", err)
	}
	return l, nil
}

// PutBlob stores blob information such as layer information in local cache
func (fs FSCache) PutBlob(blobID string, blobInfo types.BlobInfo) error {
	b, err := json.Marshal(blobInfo)
	if err != nil {
		return xerrors.Errorf("unable to marshal blob JSON (%s): %w", blobID, err)
	}
	err = fs.db.Update(func(tx *bolt.Tx) error {
		blobBucket := tx.Bucket([]byte(blobBucket))
		err = blobBucket.Put([]byte(blobID), b)
		if err != nil {
			return xerrors.Errorf("unable to store blob information in cache (%s): %w", blobID, err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("DB update error: %w", err)
	}
	return nil
}

// GetArtifact gets artifact information such as image metadata from local cache
func (fs FSCache) GetArtifact(artifactID string) (types.ArtifactInfo, error) {
	var blob []byte
	err := fs.db.View(func(tx *bolt.Tx) error {
		artifactBucket := tx.Bucket([]byte(artifactBucket))
		blob = artifactBucket.Get([]byte(artifactID))
		return nil
	})
	if err != nil {
		return types.ArtifactInfo{}, xerrors.Errorf("DB error: %w", err)
	}

	var info types.ArtifactInfo
	if err := json.Unmarshal(blob, &info); err != nil {
		return types.ArtifactInfo{}, xerrors.Errorf("JSON unmarshal error: %w", err)
	}
	return info, nil
}

// DeleteBlobs removes blobs by IDs
func (fs FSCache) DeleteBlobs(blobIDs []string) error {
	var errs error
	err := fs.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(blobBucket))
		for _, blobID := range blobIDs {
			if err := bucket.Delete([]byte(blobID)); err != nil {
				errs = multierror.Append(errs, err)
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("DB delete error: %w", err)
	}
	return errs
}

// PutArtifact stores artifact information such as image metadata in local cache
func (fs FSCache) PutArtifact(artifactID string, artifactInfo types.ArtifactInfo) (err error) {
	b, err := json.Marshal(artifactInfo)
	if err != nil {
		return xerrors.Errorf("unable to marshal artifact JSON (%s): %w", artifactID, err)
	}

	err = fs.db.Update(func(tx *bolt.Tx) error {
		artifactBucket := tx.Bucket([]byte(artifactBucket))
		err = artifactBucket.Put([]byte(artifactID), b)
		if err != nil {
			return xerrors.Errorf("unable to store artifact information in cache (%s): %w", artifactID, err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("DB update error: %w", err)
	}
	return nil
}

// MissingBlobs returns missing blob IDs such as layer IDs
func (fs FSCache) MissingBlobs(artifactID string, blobIDs []string) (bool, []string, error) {
	var missingArtifact bool
	var missingBlobIDs []string
	err := fs.db.View(func(tx *bolt.Tx) error {
		blobBucket := tx.Bucket([]byte(blobBucket))
		for _, blobID := range blobIDs {
			blobInfo, err := fs.getBlob(blobBucket, blobID)
			if err != nil {
				// error means cache missed blob info
				missingBlobIDs = append(missingBlobIDs, blobID)
				continue
			}
			if blobInfo.SchemaVersion != types.BlobJSONSchemaVersion {
				missingBlobIDs = append(missingBlobIDs, blobID)
			}
		}
		return nil
	})
	if err != nil {
		return false, nil, xerrors.Errorf("DB error: %w", err)
	}

	// get artifact info
	artifactInfo, err := fs.GetArtifact(artifactID)
	if err != nil {
		// error means cache missed artifact info
		return true, missingBlobIDs, nil
	}
	if artifactInfo.SchemaVersion != types.ArtifactJSONSchemaVersion {
		missingArtifact = true
	}
	return missingArtifact, missingBlobIDs, nil
}

// Close closes the database
func (fs FSCache) Close() error {
	if err := fs.db.Close(); err != nil {
		return xerrors.Errorf("unable to close DB: %w", err)
	}
	return nil
}

// Clear removes the database
func (fs FSCache) Clear() error {
	if err := fs.Close(); err != nil {
		return err
	}
	if err := os.RemoveAll(fs.directory); err != nil {
		return xerrors.Errorf("failed to remove cache: %w", err)
	}
	return nil
}
