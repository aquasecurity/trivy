package db

import (
	"encoding/json"

	"github.com/aquasecurity/trivy-db/pkg/types"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

func (dbc Config) PutAdvisory(tx *bolt.Tx, bktNames []string, key string, advisory interface{}) error {
	if err := dbc.put(tx, bktNames, key, advisory); err != nil {
		return xerrors.Errorf("failed to put advisory: %w", err)
	}
	return nil
}

func (dbc Config) ForEachAdvisory(sources []string, pkgName string) (map[string]Value, error) {
	return dbc.forEach(append(sources, pkgName))
}

func (dbc Config) GetAdvisories(source, pkgName string) ([]types.Advisory, error) {
	advisories, err := dbc.ForEachAdvisory([]string{source}, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("advisory foreach error: %w", err)
	}
	if len(advisories) == 0 {
		return nil, nil
	}

	var results []types.Advisory
	for vulnID, v := range advisories {
		var advisory types.Advisory
		if err = json.Unmarshal(v.Content, &advisory); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal advisory JSON: %w", err)
		}

		advisory.VulnerabilityID = vulnID
		if v.Source != (types.DataSource{}) {
			advisory.DataSource = &types.DataSource{
				ID:   v.Source.ID,
				Name: v.Source.Name,
				URL:  v.Source.URL,
			}
		}

		results = append(results, advisory)
	}
	return results, nil
}
