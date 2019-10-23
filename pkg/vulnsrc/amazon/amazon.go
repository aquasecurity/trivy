package amazon

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/vuln-list-update/amazon"
	bolt "github.com/etcd-io/bbolt"
	"golang.org/x/xerrors"
)

const (
	amazonDir      = "amazon"
	platformFormat = "amazon linux %s"
)

var (
	targetVersions = []string{"1", "2"}
	fileWalker     = utils.FileWalk // TODO: Remove once utils.go exposes an interface
)

type Operations interface {
	Update(string, map[string]struct{}) error
	Get(string, string) ([]vulnerability.Advisory, error)
}

type VulnSrc struct {
	dbc      db.Operations
	vdb      vulnerability.Operations
	bar      *utils.ProgressBar
	alasList []alas
}

type alas struct {
	Version string
	amazon.ALAS
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
		vdb: vulnerability.DB{},
	}
}

func (vs VulnSrc) Update(dir string, updatedFiles map[string]struct{}) error {
	rootDir := filepath.Join(dir, amazonDir)
	targets, err := utils.FilterTargets(amazonDir, updatedFiles) //TODO: Untested
	if err != nil {
		return xerrors.Errorf("failed to filter target files: %w", err)
	} else if len(targets) == 0 {
		log.Logger.Debug("amazon: no updated file")
		return nil
	}
	log.Logger.Debugf("Amazon Linux AMI Security Advisory updated files: %d", len(targets))

	vs.bar = utils.PbStartNew(len(targets))
	defer vs.bar.Finish()

	err = fileWalker(rootDir, targets, vs.walkFunc)
	if err != nil {
		return xerrors.Errorf("error in amazon walk: %w", err)
	}

	if err = vs.save(); err != nil {
		return xerrors.Errorf("error in amazon save: %w", err)
	}

	return nil
}

func (vs *VulnSrc) walkFunc(r io.Reader, path string) error {
	paths := strings.Split(path, string(filepath.Separator))
	if len(paths) < 2 {
		return nil
	}
	version := paths[len(paths)-2]
	if !utils.StringInSlice(version, targetVersions) {
		log.Logger.Debugf("unsupported amazon version: %s", version)
		return nil
	}

	var vuln amazon.ALAS
	if err := json.NewDecoder(r).Decode(&vuln); err != nil {
		return xerrors.Errorf("failed to decode amazon JSON: %w", err)
	}

	vs.alasList = append(vs.alasList, alas{
		Version: version,
		ALAS:    vuln,
	})
	vs.bar.Increment()
	return nil
}

func (vs VulnSrc) save() error {
	log.Logger.Debug("Saving amazon DB")
	err := vs.dbc.BatchUpdate(vs.commit())
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

// TODO: Cleanup the double layer of nested closures
func (vs VulnSrc) commit() func(tx *bolt.Tx) error {
	return vs.commitFunc
}

func (vs VulnSrc) commitFunc(tx *bolt.Tx) error {
	for _, alas := range vs.alasList {
		for _, cveID := range alas.CveIDs {
			for _, pkg := range alas.Packages {
				platformName := fmt.Sprintf(platformFormat, alas.Version)
				advisory := vulnerability.Advisory{
					VulnerabilityID: cveID,
					FixedVersion:    constructVersion(pkg.Epoch, pkg.Version, pkg.Release),
				}
				if err := vs.dbc.PutNestedBucket(tx, platformName, pkg.Name, cveID, advisory); err != nil {
					return xerrors.Errorf("failed to save amazon advisory: %w", err)
				}

				var references []string
				for _, ref := range alas.References {
					references = append(references, ref.Href)
				}

				vuln := vulnerability.Vulnerability{
					Severity:    severityFromPriority(alas.Severity),
					References:  references,
					Description: alas.Description,
					Title:       "",
				}
				if err := vs.vdb.Put(tx, cveID, vulnerability.Amazon, vuln); err != nil {
					return xerrors.Errorf("failed to save amazon vulnerability: %w", err)
				}
			}
		}
	}
	return nil
}

// Get returns a security advisory
func (vs VulnSrc) Get(version string, pkgName string) ([]vulnerability.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, version)
	advisories, err := vs.dbc.ForEach(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("error in amazon foreach: %w", err)
	}
	if len(advisories) == 0 {
		return nil, nil
	}

	var results []vulnerability.Advisory
	for _, v := range advisories {
		var advisory vulnerability.Advisory
		if err = json.Unmarshal(v, &advisory); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal amazon JSON: %w", err)
		}
		results = append(results, advisory)
	}
	return results, nil
}

func severityFromPriority(priority string) vulnerability.Severity {
	switch priority {
	case "low":
		return vulnerability.SeverityLow
	case "medium":
		return vulnerability.SeverityMedium
	case "important":
		return vulnerability.SeverityHigh
	case "critical":
		return vulnerability.SeverityCritical
	default:
		return vulnerability.SeverityUnknown
	}
}

func constructVersion(epoch, version, release string) string {
	verStr := ""
	if epoch != "0" && epoch != "" {
		verStr += fmt.Sprintf("%s:", epoch)
	}
	verStr += version

	if release != "" {
		verStr += fmt.Sprintf("-%s", release)

	}
	return verStr
}
