package alma

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	version "github.com/knqyf263/go-rpm-version"
)

const (
	almaDir = "alma"
)

var (
	platformFormat = "alma %s"

	source = types.DataSource{
		ID:   vulnerability.Alma,
		Name: "AlmaLinux Product Errata",
		URL:  "https://errata.almalinux.org/",
	}
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", almaDir)
	errata := map[string][]Erratum{}
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var erratum Erratum
		if err := json.NewDecoder(r).Decode(&erratum); err != nil {
			return xerrors.Errorf("failed to decode Alma erratum: %w", err)
		}

		dirs := strings.Split(path, string(filepath.Separator))
		if len(dirs) < 3 {
			log.Printf("invalid path: %s\n", path)
			return nil
		}

		majorVer := dirs[len(dirs)-3]
		errata[majorVer] = append(errata[majorVer], erratum)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Alma walk: %w", err)
	}

	if err = vs.save(errata); err != nil {
		return xerrors.Errorf("error in Alma save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(errataVer map[string][]Erratum) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for majorVer, errata := range errataVer {
			platformName := fmt.Sprintf(platformFormat, majorVer)
			if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
				return xerrors.Errorf("failed to put data source: %w", err)
			}

			if err := vs.commit(tx, platformName, errata); err != nil {
				return xerrors.Errorf("Alma %s commit error: %w", majorVer, err)
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in db batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, platformName string, errata []Erratum) error {
	for _, erratum := range errata {
		var references []string
		for _, ref := range erratum.References {
			if ref.Type != "cve" {
				references = append(references, ref.Href)
			}
		}

		for _, ref := range erratum.References {
			if ref.Type != "cve" {
				continue
			}

			// We need to work around this issue for now.
			// https://github.com/aquasecurity/fanal/issues/186#issuecomment-931523102
			advisories := map[string]types.Advisory{}

			cveID := ref.Title
			for _, pkg := range erratum.Pkglist.Packages {
				if pkg.Arch != "noarch" && pkg.Arch != "x86_64" {
					continue
				}

				pkgName := pkg.Name
				if erratum.Pkglist.Module.Name != "" && erratum.Pkglist.Module.Stream != "" {
					pkgName = fmt.Sprintf("%s:%s::%s", erratum.Pkglist.Module.Name, erratum.Pkglist.Module.Stream, pkg.Name)
				}

				advisory := types.Advisory{
					FixedVersion: utils.ConstructVersion(pkg.Epoch, pkg.Version, pkg.Release),
				}

				if adv, ok := advisories[pkgName]; ok {
					if version.NewVersion(advisory.FixedVersion).LessThan(version.NewVersion(adv.FixedVersion)) {
						advisories[pkgName] = advisory
					}
				} else {
					advisories[pkgName] = advisory
				}

				vuln := types.VulnerabilityDetail{
					Severity:    generalizeSeverity(erratum.Severity),
					Title:       erratum.Title,
					Description: erratum.Description,
					References:  references,
				}
				if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, source.ID, vuln); err != nil {
					return xerrors.Errorf("failed to save Alma vulnerability: %w", err)
				}

				if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
					return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
				}
			}

			for pkgName, advisory := range advisories {
				if err := vs.dbc.PutAdvisoryDetail(tx, cveID, pkgName, []string{platformName}, advisory); err != nil {
					return xerrors.Errorf("failed to save Alma advisory: %w", err)
				}
			}
		}
	}
	return nil
}

func (vs VulnSrc) Get(release, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Alma advisories: %w", err)
	}
	return advisories, nil
}

func generalizeSeverity(severity string) types.Severity {
	switch strings.ToLower(severity) {
	case "low":
		return types.SeverityLow
	case "moderate":
		return types.SeverityMedium
	case "important":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}
