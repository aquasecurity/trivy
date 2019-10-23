package nvd

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/log"

	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/utils"

	bolt "github.com/etcd-io/bbolt"

	"github.com/aquasecurity/trivy/pkg/db"
)

const (
	nvdDir = "nvd"
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

	bar := utils.PbStartNew(len(targets))
	defer bar.Finish()
	var items []Item
	buffer := &bytes.Buffer{}
	err = utils.FileWalk(rootDir, targets, func(r io.Reader, _ string) error {
		item := Item{}
		if _, err := buffer.ReadFrom(r); err != nil {
			return xerrors.Errorf("failed to read file: %w", err)
		}
		if err := json.Unmarshal(buffer.Bytes(), &item); err != nil {
			return xerrors.Errorf("failed to decode NVD JSON: %w", err)
		}
		buffer.Reset()
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

func save(items []Item) error {
	log.Logger.Debug("NVD batch update")
	vdb := vulnerability.DB{}
	err := vdb.BatchUpdate(func(b *bolt.Bucket) error {
		for _, item := range items {
			cveID := item.Cve.Meta.ID
			severity, _ := vulnerability.NewSeverity(item.Impact.BaseMetricV2.Severity)
			severityV3, _ := vulnerability.NewSeverity(item.Impact.BaseMetricV3.CvssV3.BaseSeverity)

			var references []string
			for _, ref := range item.Cve.References.ReferenceDataList {
				references = append(references, ref.URL)
			}

			var description string
			for _, d := range item.Cve.Description.DescriptionDataList {
				if d.Value != "" {
					description = d.Value
					break
				}
			}

			vuln := vulnerability.Vulnerability{
				CvssScore:   item.Impact.BaseMetricV2.CvssV2.BaseScore,
				CvssScoreV3: item.Impact.BaseMetricV3.CvssV3.BaseScore,
				Severity:    severity,
				SeverityV3:  severityV3,
				References:  references,
				Title:       "",
				Description: description,
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
