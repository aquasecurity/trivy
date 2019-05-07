package ubuntu

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"github.com/knqyf263/trivy/pkg/log"

	bolt "github.com/etcd-io/bbolt"

	"github.com/knqyf263/trivy/pkg/db"
	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/pkg/utils"
)

const (
	ubuntuDir      = "ubuntu"
	platformFormat = "ubuntu %s"
	t
)

var (
	targetStatus          = []string{"needed", "deferred", "released"}
	UbuntuReleasesMapping = map[string]string{
		"precise": "12.04",
		"quantal": "12.10",
		"raring":  "13.04",
		"trusty":  "14.04",
		"utopic":  "14.10",
		"vivid":   "15.04",
		"wily":    "15.10",
		"xenial":  "16.04",
		"yakkety": "16.10",
		"zesty":   "17.04",
		"artful":  "17.10",
		"bionic":  "18.04",
		"cosmic":  "18.10",
		"disco":   "19.04",
	}
)

func Update(dir string, updatedFiles map[string]struct{}) error {
	rootDir := filepath.Join(dir, ubuntuDir)
	targets, err := utils.FilterTargets(ubuntuDir, updatedFiles)
	if err != nil {
		return xerrors.Errorf("failed to filter target files: %w", err)
	} else if len(targets) == 0 {
		log.Logger.Debug("Ubuntu: no updated file")
		return nil
	}
	log.Logger.Debugf("Ubuntu OVAL updated files: %d", len(targets))

	bar := utils.PbStartNew(len(targets))
	defer bar.Finish()

	var cves []UbuntuCVE
	err = utils.FileWalk(rootDir, targets, func(r io.Reader, path string) error {
		var cve UbuntuCVE
		if err = json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("failed to decode Ubuntu JSON: %w", err)
		}
		cves = append(cves, cve)
		bar.Increment()
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Ubuntu walk: %w", err)
	}

	if err = save(cves); err != nil {
		return xerrors.Errorf("error in Ubuntu save: %w", err)
	}

	return nil
}

func save(cves []UbuntuCVE) error {
	log.Logger.Debug("Saving Ubuntu DB")
	err := db.BatchUpdate(func(tx *bolt.Tx) error {
		for _, cve := range cves {
			for packageName, patch := range cve.Patches {
				pkgName := string(packageName)
				for release, status := range patch {
					if !utils.StringInSlice(status.Status, targetStatus) {
						continue
					}
					osVersion, ok := UbuntuReleasesMapping[string(release)]
					if !ok {
						continue
					}
					platformName := fmt.Sprintf(platformFormat, osVersion)
					advisory := vulnerability.Advisory{
						VulnerabilityID: cve.Candidate,
					}
					if status.Status == "released" {
						advisory.FixedVersion = status.Note
					}
					if err := db.PutNestedBucket(tx, platformName, pkgName, cve.Candidate, advisory); err != nil {
						return xerrors.Errorf("failed to save Ubuntu advisory: %w", err)
					}

					vuln := vulnerability.Vulnerability{
						Severity:    severityFromPriority(cve.Priority),
						References:  cve.References,
						Description: cve.Description,
						// TODO
						Title: "",
					}
					if err := vulnerability.Put(tx, cve.Candidate, vulnerability.Ubuntu, vuln); err != nil {
						return xerrors.Errorf("failed to save Ubuntu vulnerability: %w", err)
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
		return nil, xerrors.Errorf("error in Ubuntu foreach: %w", err)
	}
	if len(advisories) == 0 {
		return nil, nil
	}

	var results []vulnerability.Advisory
	for _, v := range advisories {
		var advisory vulnerability.Advisory
		if err = json.Unmarshal(v, &advisory); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal Ubuntu JSON: %w", err)
		}
		results = append(results, advisory)
	}
	return results, nil
}

func severityFromPriority(priority string) vulnerability.Severity {
	switch priority {
	case "untriaged":
		return vulnerability.SeverityUnknown
	case "negligible", "low":
		return vulnerability.SeverityLow
	case "medium":
		return vulnerability.SeverityMedium
	case "high":
		return vulnerability.SeverityHigh
	case "critical":
		return vulnerability.SeverityCritical
	default:
		return vulnerability.SeverityUnknown
	}
}
