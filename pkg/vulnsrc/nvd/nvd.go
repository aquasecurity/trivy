package nvd

import (
	"encoding/json"
	"gopkg.in/cheggaaa/pb.v1"
	"io"
	"path/filepath"

	"github.com/knqyf263/trivy/pkg/log"

	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/pkg/utils"

	bolt "github.com/etcd-io/bbolt"
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
	} else if len(targets) == 0 {
		log.Logger.Debug("NVD: no updated file")
		return nil
	}
	log.Logger.Debugf("NVD updated files: %d", len(targets))

	bar := pb.StartNew(len(targets))
	defer bar.Finish()
	var items []vulnerability.Item
	err = utils.FileWalk(rootDir, targets, func(r io.Reader, _ string) error {
		item := vulnerability.Item{}
		if err := json.NewDecoder(r).Decode(&item); err != nil {
			return xerrors.Errorf("failed to decode NVD JSON: %w", err)
		}
		items = append(items, item)
		bar.Increment()
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

func save(items []vulnerability.Item) error {
	log.Logger.Debug("NVD batch update")
	err := vulnerability.BatchUpdate(func(b *bolt.Bucket) error {
		for _, item := range items {
			cveID := item.Cve.Meta.ID
			severity, _ := vulnerability.NewSeverity(item.Impact.BaseMetricV2.Severity)
			severityV3, _ := vulnerability.NewSeverity(item.Impact.BaseMetricV3.CvssV3.BaseSeverity)
			vuln := vulnerability.Vulnerability{
				Severity:   severity,
				SeverityV3: severityV3,
				// TODO
				References:  []string{},
				Title:       "",
				Description: "",
			}

			if err := db.Put(b, cveID, vulnerability.Nvd, vuln); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}
