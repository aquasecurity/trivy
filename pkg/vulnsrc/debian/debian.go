package debian

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/knqyf263/trivy/pkg/vulnsrc/nvd"

	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/log"

	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/utils"
)

const (
	debianDir = "debian"
)

var (
	platformFormat = "debian %s"
)

func Update(dir string, updatedFiles map[string]struct{}) error {
	rootDir := filepath.Join(dir, debianDir)
	targets, err := utils.FilterTargets(debianDir, updatedFiles)
	if err != nil {
		return xerrors.Errorf("failed to filter target files: %w", err)
	}

	var cves []DebianCVE
	err = utils.FileWalk(rootDir, targets, func(r io.Reader, path string) error {
		var cve DebianCVE
		if err = json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("failed to decode RedHat JSON: %w", err)
		}

		cve.VulnerabilityID = strings.TrimSuffix(filepath.Base(path), ".json")
		cve.Package = filepath.Base(filepath.Dir(path))
		cves = append(cves, cve)

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

// platformName: pkgStatus
type platform map[string]pkg

// pkgName: advisoryStatus
type pkg map[string]advisory

// cveID: version
type advisory map[string]interface{}

func save(cves []DebianCVE) error {
	data := platform{}
	for _, cve := range cves {
		for _, release := range cve.Releases {
			if release.Status != "open" {
				continue
			}
			for platformName := range release.Repositories {
				platformName = fmt.Sprintf(platformFormat, platformName)
				p, ok := data[platformName]
				if !ok {
					data[platformName] = pkg{}
					p = data[platformName]
				}

				pkgName := cve.Package
				a, ok := p[pkgName]
				if !ok {
					p[pkgName] = advisory{}
					a = p[pkgName]
				}

				a[cve.VulnerabilityID] = Advisory{
					VulnerabilityID: cve.VulnerabilityID,
					Severity:        severityFromUrgency(release.Urgency),
				}
			}
		}
	}

	log.Logger.Debug("Saving Debian DB")
	for platform, pkgs := range data {
		bucketKV := map[string]map[string]interface{}{}
		for pkg, advisory := range pkgs {
			bucketKV[pkg] = map[string]interface{}(advisory)
		}
		if err := db.BatchUpdate(platform, bucketKV); err != nil {
			return xerrors.Errorf("error in db batch update: %w", err)
		}
	}
	return nil
}

func Get(release string, pkgName string) ([]Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := db.ForEach(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("error in Debian foreach: %w", err)
	}
	if len(advisories) == 0 {
		return nil, nil
	}

	var results []Advisory
	for _, v := range advisories {
		var advisory Advisory
		if err = json.Unmarshal(v, &advisory); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal Debian JSON: %w", err)
		}
		results = append(results, advisory)
	}
	return results, nil
}

func severityFromUrgency(urgency string) nvd.Severity {
	switch urgency {
	case "not yet assigned":
		return nvd.SeverityUnknown

	case "end-of-life", "unimportant", "low", "low*", "low**":
		return nvd.SeverityLow

	case "medium", "medium*", "medium**":
		return nvd.SeverityMedium

	case "high", "high*", "high**":
		return nvd.SeverityHigh
	default:
		return nvd.SeverityUnknown
	}
}
