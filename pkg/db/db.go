package db

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/log"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/utils"

	bolt "github.com/etcd-io/bbolt"
)

var (
	db    *bolt.DB
	dbDir string
)

type Operations interface {
	SetVersion(string) error
	Update(string, string, string, interface{}) error
	BatchUpdate(func(*bolt.Tx) error) error
	PutNestedBucket(*bolt.Tx, string, string, string, interface{}) error
	ForEach(string, string) (map[string][]byte, error)
}

type Config struct {
}

func Init() (err error) {
	dbDir = filepath.Join(utils.CacheDir(), "db")
	if err = os.MkdirAll(dbDir, 0700); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	dbPath := filepath.Join(dbDir, "trivy.db")
	log.Logger.Debugf("db path: %s", dbPath)
	db, err = bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return xerrors.Errorf("failed to open db: %w", err)
	}
	return nil
}

func Close() error {
	if err := db.Close(); err != nil {
		return xerrors.Errorf("failed to close DB: %w", err)
	}
	return nil
}

func Reset() error {
	if err := Close(); err != nil {
		return xerrors.Errorf("failed to reset DB: %w", err)
	}

	if err := os.RemoveAll(dbDir); err != nil {
		return xerrors.Errorf("failed to reset DB: %w", err)
	}

	if err := Init(); err != nil {
		return xerrors.Errorf("failed to reset DB: %w", err)
	}
	return nil
}

func GetVersion() string {
	var version string
	value, err := Get("trivy", "metadata", "version")
	if err != nil {
		return ""
	}
	if err = json.Unmarshal(value, &version); err != nil {
		return ""
	}
	return version
}

func (dbc Config) SetVersion(version string) error {
	err := dbc.Update("trivy", "metadata", "version", version)
	if err != nil {
		return xerrors.Errorf("failed to save DB version: %w", err)
	}
	return nil
}

func (dbc Config) Update(rootBucket, nestedBucket, key string, value interface{}) error {
	err := db.Update(func(tx *bolt.Tx) error {
		return dbc.PutNestedBucket(tx, rootBucket, nestedBucket, key, value)
	})
	if err != nil {
		return xerrors.Errorf("error in db update: %w", err)
	}
	return err
}

func (dbc Config) PutNestedBucket(tx *bolt.Tx, rootBucket, nestedBucket, key string, value interface{}) error {
	root, err := tx.CreateBucketIfNotExists([]byte(rootBucket))
	if err != nil {
		return xerrors.Errorf("failed to create a bucket: %w", err)
	}
	return Put(root, nestedBucket, key, value)
}

func Put(root *bolt.Bucket, nestedBucket, key string, value interface{}) error {
	nested, err := root.CreateBucketIfNotExists([]byte(nestedBucket))
	if err != nil {
		return xerrors.Errorf("failed to create a bucket: %w", err)
	}
	v, err := json.Marshal(value)
	if err != nil {
		return xerrors.Errorf("failed to unmarshal JSON: %w", err)
	}
	return nested.Put([]byte(key), v)
}

func (dbc Config) BatchUpdate(fn func(tx *bolt.Tx) error) error {
	err := db.Batch(fn)
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
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
		return nil, xerrors.Errorf("failed to get data from db: %w", err)
	}
	return value, nil
}

func (dbc Config) ForEach(rootBucket, nestedBucket string) (value map[string][]byte, err error) {
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
			return xerrors.Errorf("error in db foreach: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to get all key/value in the specified bucket: %w", err)
	}
	return value, nil
}
