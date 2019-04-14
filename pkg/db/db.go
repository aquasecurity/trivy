package db

import (
	"encoding/json"

	bolt "github.com/etcd-io/bbolt"
)

var (
	db *bolt.DB
)

func Init() (err error) {
	db, err = bolt.Open("/tmp/my.db", 0600, nil)
	if err != nil {
		return err
	}
	return nil
}

func Update(bucket, key string, value interface{}) error {
	err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		v, err := json.Marshal(value)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), v)
	})
	return err
}

func BatchUpdate(bucket string, kv map[string]interface{}) error {
	err := db.Batch(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		for k, v := range kv {
			value, err := json.Marshal(v)
			if err != nil {
				return err
			}
			if err = b.Put([]byte(k), value); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func Get(bucket, key string) (value []byte, err error) {
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		value = b.Get([]byte(key))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return value, nil
}
