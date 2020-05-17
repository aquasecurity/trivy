package cache

import (
	"encoding/json"
	"github.com/aquasecurity/fanal/types"
	"github.com/google/go-containerregistry/pkg/v1"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
	"os"
	"path/filepath"
)

const (
	cacheDirName = "fanal"

	// imageBucket stores image information with image ID
	imageBucket = "image"
	// layerBucket stores os, package and library information per layer ID
	layerBucket = "layer"
)

type Cache interface {
	ImageCache
	LocalImageCache
}

// ImageCache uses local or remote cache
type ImageCache interface {
	MissingLayers(imageID string, layerIDs []string) (missingImage bool, missingLayerIDs []string, err error)
	PutImage(imageID string, imageInfo types.ImageInfo) (err error)
	PutLayer(diffID string, layerInfo types.LayerInfo) (err error)
}

// LocalImageCache always uses local cache
type LocalImageCache interface {
	GetImage(imageID string) (imageInfo types.ImageInfo, err error)
	GetLayer(diffID string) (layerInfo types.LayerInfo, err error)
	Close() (err error)
	Clear() (err error)
}

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
		for _, bucket := range []string{imageBucket, layerBucket} {
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

func (fs FSCache) GetLayer(diffID string) (types.LayerInfo, error) {
	var layerInfo types.LayerInfo
	err := fs.db.View(func(tx *bolt.Tx) error {
		var err error
		layerBucket := tx.Bucket([]byte(layerBucket))
		layerInfo, err = fs.getLayer(layerBucket, diffID)
		if err != nil {
			return xerrors.Errorf("failed to get layer from the cache: %w", err)
		}
		return nil
	})
	if err != nil {
		return types.LayerInfo{}, xerrors.Errorf("DB error: %w", err)
	}
	return layerInfo, nil
}

func (fs FSCache) getLayer(layerBucket *bolt.Bucket, diffID string) (types.LayerInfo, error) {
	b := layerBucket.Get([]byte(diffID))

	var l types.LayerInfo
	if err := json.Unmarshal(b, &l); err != nil {
		return types.LayerInfo{}, xerrors.Errorf("JSON unmarshal error: %w", err)
	}
	return l, nil
}

func (fs FSCache) PutLayer(diffID string, layerInfo types.LayerInfo) error {
	if _, err := v1.NewHash(diffID); err != nil {
		return xerrors.Errorf("invalid diffID (%s): %w", diffID, err)
	}

	b, err := json.Marshal(layerInfo)
	if err != nil {
		return xerrors.Errorf("unable to marshal layer JSON (%s): %w", diffID, err)
	}
	err = fs.db.Update(func(tx *bolt.Tx) error {
		layerBucket := tx.Bucket([]byte(layerBucket))
		err = layerBucket.Put([]byte(diffID), b)
		if err != nil {
			return xerrors.Errorf("unable to store layer information in cache (%s): %w", diffID, err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("DB update error: %w", err)
	}
	return nil
}

func (fs FSCache) GetImage(imageID string) (types.ImageInfo, error) {
	var blob []byte
	err := fs.db.View(func(tx *bolt.Tx) error {
		imageBucket := tx.Bucket([]byte(imageBucket))
		blob = imageBucket.Get([]byte(imageID))
		return nil
	})
	if err != nil {
		return types.ImageInfo{}, xerrors.Errorf("DB error: %w", err)
	}

	var info types.ImageInfo
	if err := json.Unmarshal(blob, &info); err != nil {
		return types.ImageInfo{}, xerrors.Errorf("JSON unmarshal error: %w", err)
	}
	return info, nil
}

func (fs FSCache) PutImage(imageID string, imageConfig types.ImageInfo) (err error) {
	b, err := json.Marshal(imageConfig)
	if err != nil {
		return xerrors.Errorf("unable to marshal image JSON (%s): %w", imageID, err)
	}

	err = fs.db.Update(func(tx *bolt.Tx) error {
		imageBucket := tx.Bucket([]byte(imageBucket))
		err = imageBucket.Put([]byte(imageID), b)
		if err != nil {
			return xerrors.Errorf("unable to store image information in cache (%s): %w", imageID, err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("DB update error: %w", err)
	}
	return nil
}

func (fs FSCache) MissingLayers(imageID string, layerIDs []string) (bool, []string, error) {
	var missingImage bool
	var missingLayerIDs []string
	err := fs.db.View(func(tx *bolt.Tx) error {
		layerBucket := tx.Bucket([]byte(layerBucket))
		for _, layerID := range layerIDs {
			layerInfo, err := fs.getLayer(layerBucket, layerID)
			if err != nil {
				// error means cache missed layer info
				missingLayerIDs = append(missingLayerIDs, layerID)
				continue
			}
			if layerInfo.SchemaVersion != types.LayerJSONSchemaVersion {
				missingLayerIDs = append(missingLayerIDs, layerID)
			}
		}
		return nil
	})
	if err != nil {
		return false, nil, xerrors.Errorf("DB error: %w", err)
	}

	// get image info
	imageInfo, err := fs.GetImage(imageID)
	if err != nil {
		// error means cache missed image info
		return true, missingLayerIDs, nil
	}
	if imageInfo.SchemaVersion != types.ImageJSONSchemaVersion {
		missingImage = true
	}
	return missingImage, missingLayerIDs, nil
}

func (fs FSCache) Close() error {
	if err := fs.db.Close(); err != nil {
		return xerrors.Errorf("unable to close DB: %w", err)
	}
	return nil
}

func (fs FSCache) Clear() error {
	if err := fs.Close(); err != nil {
		return err
	}
	if err := os.RemoveAll(fs.directory); err != nil {
		return xerrors.Errorf("failed to remove cache: %w", err)
	}
	return nil
}
