package db

import (
	"encoding/json"

	"github.com/aquasecurity/trivy-db/pkg/types"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const (
	dataSourceBucket = "data-source"
)

func (dbc Config) PutDataSource(tx *bolt.Tx, bktName string, source types.DataSource) error {
	bucket, err := tx.CreateBucketIfNotExists([]byte(dataSourceBucket))
	if err != nil {
		return xerrors.Errorf("failed to create %s bucket: %w", dataSourceBucket, err)
	}
	b, err := json.Marshal(source)
	if err != nil {
		return xerrors.Errorf("JSON marshal error: %w", err)
	}

	return bucket.Put([]byte(bktName), b)
}

func (dbc Config) getDataSource(tx *bolt.Tx, bktName string) (types.DataSource, error) {
	bucket := tx.Bucket([]byte(dataSourceBucket))
	if bucket == nil {
		return types.DataSource{}, nil
	}

	b := bucket.Get([]byte(bktName))
	if b == nil {
		return types.DataSource{}, nil
	}

	var source types.DataSource
	if err := json.Unmarshal(b, &source); err != nil {
		return types.DataSource{}, xerrors.Errorf("JSON unmarshal error: %w", err)
	}

	return source, nil
}
