package db

import (
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const (
	vulnerabilityIDBucket = "vulnerability-id"
)

func (dbc Config) PutVulnerabilityID(tx *bolt.Tx, vulnID string) error {
	bucket, err := tx.CreateBucketIfNotExists([]byte(vulnerabilityIDBucket))
	if err != nil {
		return xerrors.Errorf("failed to create %s bucket: %w", vulnerabilityIDBucket, err)
	}
	return bucket.Put([]byte(vulnID), []byte("{}"))
}

func (dbc Config) ForEachVulnerabilityID(f func(tx *bolt.Tx, vulnID string) error) error {
	err := db.Batch(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(vulnerabilityIDBucket))
		if bucket == nil {
			return xerrors.Errorf("no such bucket: %s", vulnerabilityIDBucket)
		}
		err := bucket.ForEach(func(vulnID, _ []byte) error {
			if err := f(tx, string(vulnID)); err != nil {
				return xerrors.Errorf("something wrong: %w", err)
			}
			return nil
		})
		if err != nil {
			return xerrors.Errorf("error in for each: %w", err)
		}
		return nil
	})
	return err
}

func (dbc Config) DeleteVulnerabilityIDBucket() error {
	return dbc.deleteBucket(vulnerabilityIDBucket)
}
