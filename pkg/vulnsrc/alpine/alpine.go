package alpine

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"

	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"

	"golang.org/x/xerrors"

	bolt "github.com/etcd-io/bbolt"
	"github.com/aquasecurity/trivy/pkg/utils"
)

const (
	alpineDir = "alpine"
)

var (
	platformFormat = "alpine %s"
)

func Update(dir string, updatedFiles map[string]struct{}) error {
	rootDir := filepath.Join(dir, alpineDir)
	targets, err := utils.FilterTargets(alpineDir, updatedFiles)
	if err != nil {
		return xerrors.Errorf("failed to filter target files: %w", err)
	} else if len(targets) == 0 {
		log.Logger.Debug("Alpine: no updated file")
		return nil
	}
	log.Logger.Debugf("Alpine updated files: %d", len(targets))

	bar := utils.PbStartNew(len(targets))
	defer bar.Finish()

	var cves []AlpineCVE
	err = utils.FileWalk(rootDir, targets, func(r io.Reader, path string) error {
		var cve AlpineCVE
		if err = json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("failed to decode Alpine JSON: %w", err)
		}
		cves = append(cves, cve)
		bar.Increment()
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Alpine walk: %w", err)
	}

	if err = save(cves); err != nil {
		return xerrors.Errorf("error in Alpine save: %w", err)
	}

	return nil
}

func save(cves []AlpineCVE) error {
	log.Logger.Debug("Saving Alpine DB")

	err := db.BatchUpdate(func(tx *bolt.Tx) error {
		for _, cve := range cves {
			platformName := fmt.Sprintf(platformFormat, cve.Release)
			pkgName := cve.Package
			advisory := Advisory{
				VulnerabilityID: cve.VulnerabilityID,
				FixedVersion:    cve.FixedVersion,
				Repository:      cve.Repository,
			}
			if err := db.PutNestedBucket(tx, platformName, pkgName, cve.VulnerabilityID, advisory); err != nil {
				return xerrors.Errorf("failed to save alpine advisory: %w", err)
			}

			vuln := vulnerability.Vulnerability{
				Title:       cve.Subject,
				Description: cve.Description,
			}
			if err := vulnerability.Put(tx, cve.VulnerabilityID, vulnerability.Alpine, vuln); err != nil {
				return xerrors.Errorf("failed to save alpine vulnerability: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in db batch update: %w", err)
	}
	return nil
}

func Get(release string, pkgName string) ([]Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := db.ForEach(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("error in Alpine foreach: %w", err)
	}

	var results []Advisory
	for _, v := range advisories {
		var advisory Advisory
		if err = json.Unmarshal(v, &advisory); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal Alpine JSON: %w", err)
		}
		results = append(results, advisory)
	}
	return results, nil
}
