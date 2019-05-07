package debian

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	bolt "github.com/etcd-io/bbolt"
	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/utils"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"
	"golang.org/x/xerrors"
)

const (
	debianDir = "debian"
)

var (
	// e.g. debian 8
	platformFormat        = "debian %s"
	DebianReleasesMapping = map[string]string{
		// Code names
		"squeeze": "6",
		"wheezy":  "7",
		"jessie":  "8",
		"stretch": "9",
		"buster":  "10",
		"sid":     "unstable",
	}
)

func Update(dir string, updatedFiles map[string]struct{}) error {
	rootDir := filepath.Join(dir, debianDir)
	targets, err := utils.FilterTargets(debianDir, updatedFiles)
	if err != nil {
		return xerrors.Errorf("failed to filter target files: %w", err)
	} else if len(targets) == 0 {
		log.Logger.Debug("Debian: no updated file")
		return nil
	}
	log.Logger.Debugf("Debian updated files: %d", len(targets))

	bar := utils.PbStartNew(len(targets))
	defer bar.Finish()

	var cves []DebianCVE
	err = utils.FileWalk(rootDir, targets, func(r io.Reader, path string) error {
		var cve DebianCVE
		if err = json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("failed to decode Debian JSON: %w", err)
		}

		cve.VulnerabilityID = strings.TrimSuffix(filepath.Base(path), ".json")
		cve.Package = filepath.Base(filepath.Dir(path))
		cves = append(cves, cve)

		bar.Increment()
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Debian walk: %w", err)
	}

	if err = save(cves); err != nil {
		return xerrors.Errorf("error in Debian save: %w", err)
	}

	return nil
}

func save(cves []DebianCVE) error {
	log.Logger.Debug("Saving Debian DB")
	err := db.BatchUpdate(func(tx *bolt.Tx) error {
		for _, cve := range cves {
			for _, release := range cve.Releases {
				for releaseStr := range release.Repositories {
					majorVersion, ok := DebianReleasesMapping[releaseStr]
					if !ok {
						continue
					}
					platformName := fmt.Sprintf(platformFormat, majorVersion)
					if release.Status != "open" {
						continue
					}
					advisory := vulnerability.Advisory{
						VulnerabilityID: cve.VulnerabilityID,
						//Severity:        severityFromUrgency(release.Urgency),
					}
					if err := db.PutNestedBucket(tx, platformName, cve.Package, cve.VulnerabilityID, advisory); err != nil {
						return xerrors.Errorf("failed to save Debian advisory: %w", err)
					}

					vuln := vulnerability.Vulnerability{
						Severity:    severityFromUrgency(release.Urgency),
						Description: cve.Description,
					}

					if err := vulnerability.Put(tx, cve.VulnerabilityID, vulnerability.Debian, vuln); err != nil {
						return xerrors.Errorf("failed to save Debian vulnerability: %w", err)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}

	return nil
}

func Get(release string, pkgName string) ([]vulnerability.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := db.ForEach(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("error in Debian foreach: %w", err)
	}
	if len(advisories) == 0 {
		return nil, nil
	}

	var results []vulnerability.Advisory
	for _, v := range advisories {
		var advisory vulnerability.Advisory
		if err = json.Unmarshal(v, &advisory); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal Debian JSON: %w", err)
		}
		results = append(results, advisory)
	}
	return results, nil
}

func severityFromUrgency(urgency string) vulnerability.Severity {
	switch urgency {
	case "not yet assigned":
		return vulnerability.SeverityUnknown

	case "end-of-life", "unimportant", "low", "low*", "low**":
		return vulnerability.SeverityLow

	case "medium", "medium*", "medium**":
		return vulnerability.SeverityMedium

	case "high", "high*", "high**":
		return vulnerability.SeverityHigh
	default:
		return vulnerability.SeverityUnknown
	}
}
