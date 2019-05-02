package db

import (
	"encoding/json"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/utils"

	bolt "github.com/etcd-io/bbolt"
)

var (
	db *bolt.DB
)

func Init() (err error) {
	dbDir := filepath.Join(utils.CacheDir(), "db")
	if err = os.MkdirAll(dbDir, 0700); err != nil {
		return err
	}

	dbPath := filepath.Join(dbDir, "trivy.db")
	db, err = bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return err
	}
	return nil
}

func Update(rootBucket, nestedBucket, key string, value interface{}) error {
	err := db.Update(func(tx *bolt.Tx) error {
		root, err := tx.CreateBucketIfNotExists([]byte(rootBucket))
		if err != nil {
			return err
		}
		nested, err := root.CreateBucketIfNotExists([]byte(nestedBucket))
		if err != nil {
			return err
		}
		v, err := json.Marshal(value)
		if err != nil {
			return err
		}
		return nested.Put([]byte(key), v)
	})
	return err
}

func BatchUpdate(rootBucket string, bucketKV map[string]map[string]interface{}) error {
	err := db.Batch(func(tx *bolt.Tx) error {
		root, err := tx.CreateBucketIfNotExists([]byte(rootBucket))
		if err != nil {
			return err
		}
		for nestedBucket, kv := range bucketKV {
			nested, err := root.CreateBucketIfNotExists([]byte(nestedBucket))
			if err != nil {
				return xerrors.Errorf("failed to get bucket: %w", err)
			}
			for k, v := range kv {
				value, err := json.Marshal(v)
				if err != nil {
					return xerrors.Errorf("failed to marshal json: %w", err)
				}
				if err = nested.Put([]byte(k), value); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return err
}

func Get(rootBucket, nestedBucket, key string) (value []byte, err error) {
	err = db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte(rootBucket))
		if root == nil {
			return nil
		}
		nested := root.Bucket([]byte(nestedBucket))
		if nested == nil {
			return nil
		}
		value = nested.Get([]byte(key))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return value, nil
}

func ForEach(rootBucket, nestedBucket string) (value map[string][]byte, err error) {
	value = map[string][]byte{}
	err = db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte(rootBucket))
		if root == nil {
			return nil
		}
		nested := root.Bucket([]byte(nestedBucket))
		if nested == nil {
			return nil
		}
		err := nested.ForEach(func(k, v []byte) error {
			value[string(k)] = v
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return value, nil
}
