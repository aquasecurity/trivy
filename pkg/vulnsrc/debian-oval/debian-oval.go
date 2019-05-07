package debianoval

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/knqyf263/trivy/pkg/vulnsrc/debian"

	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	bolt "github.com/etcd-io/bbolt"
	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/log"

	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/pkg/utils"
)

var (
	debianDir = filepath.Join("oval", "debian")
	// e.g. debian oval 8
	platformFormat = "debian oval %s"
)

func Update(dir string, updatedFiles map[string]struct{}) error {
	rootDir := filepath.Join(dir, debianDir)
	targets, err := utils.FilterTargets(debianDir, updatedFiles)
	if err != nil {
		return xerrors.Errorf("failed to filter target files: %w", err)
	} else if len(targets) == 0 {
		log.Logger.Debug("Debian OVAL: no updated file")
		return nil
	}
	log.Logger.Debugf("Debian OVAL updated files: %d", len(targets))

	bar := utils.PbStartNew(len(targets))
	defer bar.Finish()

	var cves []DebianOVAL
	err = utils.FileWalk(rootDir, targets, func(r io.Reader, path string) error {
		var cve DebianOVAL
		if err = json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("failed to decode Debian OVAL JSON: %w", err)
		}

		dirs := strings.Split(path, string(os.PathSeparator))
		if len(dirs) < 3 {
			log.Logger.Debugf("invalid path: %s", path)
			return nil
		}
		cve.Release = dirs[len(dirs)-3]
		cves = append(cves, cve)
		bar.Increment()
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Debian OVAL walk: %w", err)
	}

	if err = save(cves); err != nil {
		return xerrors.Errorf("error in Debian OVAL save: %w", err)
	}

	return nil
}

// from https://github.com/kotakanbe/goval-dictionary/blob/c462c07a5cd0b6de52f167e9aa4298083edfc356/models/debian.go#L53
func walkDebian(cri Criteria, pkgs []Package) []Package {
	for _, c := range cri.Criterions {
		ss := strings.Split(c.Comment, " DPKG is earlier than ")
		if len(ss) != 2 {
			continue
		}

		// "0" means notyetfixed or erroneous information.
		// Not available because "0" includes erroneous info...
		if ss[1] == "0" {
			continue
		}
		pkgs = append(pkgs, Package{
			Name:         ss[0],
			FixedVersion: strings.Split(ss[1], " ")[0],
		})
	}

	if len(cri.Criterias) == 0 {
		return pkgs
	}
	for _, c := range cri.Criterias {
		pkgs = walkDebian(c, pkgs)
	}
	return pkgs
}

func save(cves []DebianOVAL) error {
	log.Logger.Debug("Saving Debian OVAL")
	err := db.BatchUpdate(func(tx *bolt.Tx) error {
		for _, cve := range cves {
			affectedPkgs := walkDebian(cve.Criteria, []Package{})
			for _, affectedPkg := range affectedPkgs {
				// stretch => 9
				majorVersion, ok := debian.DebianReleasesMapping[cve.Release]
				if !ok {
					continue
				}
				platformName := fmt.Sprintf(platformFormat, majorVersion)
				cveID := cve.Metadata.Title
				advisory := vulnerability.Advisory{
					VulnerabilityID: cveID,
					FixedVersion:    affectedPkg.FixedVersion,
				}
				if err := db.PutNestedBucket(tx, platformName, affectedPkg.Name, cveID, advisory); err != nil {
					return xerrors.Errorf("failed to save Debian OVAL advisory: %w", err)
				}

				var references []string
				for _, ref := range cve.Metadata.References {
					references = append(references, ref.RefURL)
				}

				vuln := vulnerability.Vulnerability{
					Description: cve.Metadata.Description,
					References:  references,
				}

				if err := vulnerability.Put(tx, cveID, vulnerability.DebianOVAL, vuln); err != nil {
					return xerrors.Errorf("failed to save Debian OVAL vulnerability: %w", err)
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
		return nil, xerrors.Errorf("error in Debian OVAL foreach: %w", err)
	}
	if len(advisories) == 0 {
		return nil, nil
	}

	var results []vulnerability.Advisory
	for _, v := range advisories {
		var advisory vulnerability.Advisory
		if err = json.Unmarshal(v, &advisory); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal Debian OVAL JSON: %w", err)
		}
		results = append(results, advisory)
	}
	return results, nil
}
