package cache

import (
	"os"
	"path/filepath"

	bolt "github.com/simar7/gokv/bbolt"
	"github.com/simar7/gokv/encoding"
	kvtypes "github.com/simar7/gokv/types"
	"golang.org/x/xerrors"
)

type Cache interface {
	Get(bucket, key string, value *[]byte) (found bool, err error)
	Set(bucket, key string, value []byte) (err error)
	Clear() error
}

type RealCache struct {
	directory string
	cache     *bolt.Store
}

func New(cacheDir string) (Cache, error) {
	dir := filepath.Join(cacheDir, "fanal")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, xerrors.Errorf("unable to create cache dir: %w", err)
	}

	cacheOptions := bolt.Options{
		RootBucketName: "fanal",
		Path:           filepath.Join(dir, "cache.db"),
		Codec:          encoding.Raw,
	}

	kv, err := bolt.NewStore(cacheOptions)
	if err != nil {
		return nil, xerrors.Errorf("error initializing cache: %w", err)
	}

	return &RealCache{directory: dir, cache: kv}, nil
}

func (rc RealCache) Get(bucket, key string, value *[]byte) (bool, error) {
	return rc.cache.Get(kvtypes.GetItemInput{
		BucketName: bucket,
		Key:        key,
		Value:      value,
	})
}

func (rc RealCache) Set(bucket, key string, value []byte) error {
	return rc.cache.BatchSet(kvtypes.BatchSetItemInput{
		BucketName: bucket,
		Keys:       []string{key},
		Values:     value,
	})
}

func (rc RealCache) Clear() error {
	if err := os.RemoveAll(rc.directory); err != nil {
		return xerrors.Errorf("failed to remove cache: %w", err)
	}
	return nil
}
