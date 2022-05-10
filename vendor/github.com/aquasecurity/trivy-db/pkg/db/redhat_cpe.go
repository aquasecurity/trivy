package db

import (
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const (
	redhatCPERootBucket = "Red Hat CPE"
	redhatRepoBucket    = "repository"
	redhatNVRBucket     = "nvr"

	// This bucket will not be used during vulnerability scanning. Just for debugging.
	redhatCPEBucket = "cpe"
)

func (dbc Config) PutRedHatRepositories(tx *bolt.Tx, repository string, cpeIndices []int) error {
	if err := dbc.put(tx, []string{redhatCPERootBucket, redhatRepoBucket}, repository, cpeIndices); err != nil {
		return xerrors.Errorf("Red Hat CPE error: %w", err)
	}

	return nil
}

func (dbc Config) PutRedHatNVRs(tx *bolt.Tx, nvr string, cpeIndices []int) error {
	if err := dbc.put(tx, []string{redhatCPERootBucket, redhatNVRBucket}, nvr, cpeIndices); err != nil {
		return xerrors.Errorf("Red Hat CPE error: %w", err)
	}

	return nil
}

func (dbc Config) PutRedHatCPEs(tx *bolt.Tx, cpeIndex int, cpe string) error {
	index := fmt.Sprint(cpeIndex)
	if err := dbc.put(tx, []string{redhatCPERootBucket, redhatCPEBucket}, index, cpe); err != nil {
		return xerrors.Errorf("Red Hat CPE error: %w", err)
	}

	return nil
}

func (dbc Config) RedHatRepoToCPEs(repository string) ([]int, error) {
	return dbc.getCPEs(redhatRepoBucket, repository)
}

func (dbc Config) RedHatNVRToCPEs(repository string) ([]int, error) {
	return dbc.getCPEs(redhatNVRBucket, repository)
}

func (dbc Config) getCPEs(bucket, key string) ([]int, error) {
	value, err := dbc.get([]string{redhatCPERootBucket, bucket}, key)
	if err != nil {
		return nil, xerrors.Errorf("unable to get '%s': %w", key, err)
	} else if len(value) == 0 {
		return nil, nil
	}

	var cpes []int
	if err = json.Unmarshal(value, &cpes); err != nil {
		return nil, xerrors.Errorf("JSON unmarshal error: %w", err)
	}
	return cpes, nil
}
