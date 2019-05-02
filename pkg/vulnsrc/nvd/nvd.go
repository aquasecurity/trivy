package nvd

import (
	"encoding/json"
	"io"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/utils"

	"github.com/knqyf263/trivy/pkg/db"
)

const (
	nvdDir       = "nvd"
	rootBucket   = "NVD"
	nestedBucket = "dummy"
)

func Update(dir string, updatedFiles map[string]struct{}) error {
	rootDir := filepath.Join(dir, nvdDir)
	targets, err := utils.FilterTargets(nvdDir, updatedFiles)
	if err != nil {
		return xerrors.Errorf("failed to filter target files: %w", err)
	}

	var items []Item
	err = utils.FileWalk(rootDir, targets, func(r io.Reader, _ string) error {
		item := Item{}
		if err := json.NewDecoder(r).Decode(&item); err != nil {
			return xerrors.Errorf("failed to decode NVD JSON: %w", err)
		}
		items = append(items, item)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in NVD walk: %w", err)
	}

	if err = save(items); err != nil {
		return xerrors.Errorf("error in NVD save: %w", err)
	}

	return nil
}

func save(items []Item) error {
	data := map[string]interface{}{}
	for _, item := range items {
		cveID := item.Cve.Meta.ID
		data[cveID] = item
	}
	d := map[string]map[string]interface{}{
		nestedBucket: data,
	}
	return db.BatchUpdate(rootBucket, d)
}

func Get(cveID string) (*Item, error) {
	value, err := db.Get(rootBucket, nestedBucket, cveID)
	if err != nil {
		return nil, xerrors.Errorf("error in NVD get: %w", err)
	}
	if len(value) == 0 {
		return nil, nil
	}

	var item *Item
	if err = json.Unmarshal(value, &item); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal NVD JSON: %w", err)
	}
	return item, nil
}
