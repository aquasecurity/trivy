package amazon

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
	ustrings "github.com/aquasecurity/trivy-db/pkg/utils/strings"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	amazonDir      = "amazon"
	platformFormat = "amazon linux %s"
)

var (
	targetVersions = []string{"1", "2"}

	source = types.DataSource{
		ID:   vulnerability.Amazon,
		Name: "Amazon Linux Security Center",
		URL:  "https://alas.aws.amazon.com/",
	}
)

type VulnSrc struct {
	dbc        db.Operation
	advisories map[string][]ALAS
}

// ALAS has detailed data of ALAS
type ALAS struct {
	ID          string      `json:"id,omitempty"`
	Title       string      `json:"title,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	Description string      `json:"description,omitempty"`
	Packages    []Package   `json:"packages,omitempty"`
	References  []Reference `json:"references,omitempty"`
	CveIDs      []string    `json:"cveids,omitempty"`
}

// Package has affected package information
type Package struct {
	Name    string `json:"name,omitempty"`
	Epoch   string `json:"epoch,omitempty"`
	Version string `json:"version,omitempty"`
	Release string `json:"release,omitempty"`
	Arch    string `json:"arch,omitempty"`
}

// Reference has reference information
type Reference struct {
	Href string `json:"href,omitempty"`
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:        db.Config{},
		advisories: map[string][]ALAS{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", amazonDir)

	err := utils.FileWalk(rootDir, vs.walkFunc)
	if err != nil {
		return xerrors.Errorf("error in Amazon walk: %w", err)
	}

	if err = vs.save(); err != nil {
		return xerrors.Errorf("error in Amazon save: %w", err)
	}

	return nil
}

func (vs *VulnSrc) walkFunc(r io.Reader, path string) error {
	paths := strings.Split(path, string(filepath.Separator))
	if len(paths) < 2 {
		return nil
	}
	version := paths[len(paths)-2]
	if !ustrings.InSlice(version, targetVersions) {
		log.Printf("unsupported Amazon version: %s\n", version)
		return nil
	}

	var alas ALAS
	if err := json.NewDecoder(r).Decode(&alas); err != nil {
		return xerrors.Errorf("failed to decode Amazon JSON: %w", err)
	}

	vs.advisories[version] = append(vs.advisories[version], alas)
	return nil
}

func (vs VulnSrc) save() error {
	log.Println("Saving Amazon DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx) error {
	for majorVersion, alasList := range vs.advisories {
		platformName := fmt.Sprintf(platformFormat, majorVersion)
		if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}
		for _, alas := range alasList {
			for _, cveID := range alas.CveIDs {
				for _, pkg := range alas.Packages {
					advisory := types.Advisory{
						FixedVersion: utils.ConstructVersion(pkg.Epoch, pkg.Version, pkg.Release),
					}
					if err := vs.dbc.PutAdvisoryDetail(tx, cveID, pkg.Name, []string{platformName}, advisory); err != nil {
						return xerrors.Errorf("failed to save Amazon advisory: %w", err)
					}

					var references []string
					for _, ref := range alas.References {
						references = append(references, ref.Href)
					}

					vuln := types.VulnerabilityDetail{
						Severity:    severityFromPriority(alas.Severity),
						References:  references,
						Description: alas.Description,
						Title:       "",
					}
					if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, source.ID, vuln); err != nil {
						return xerrors.Errorf("failed to save Amazon vulnerability detail: %w", err)
					}

					// for optimization
					if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
						return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
					}
				}
			}
		}
	}
	return nil
}

// Get returns a security advisory
func (vs VulnSrc) Get(version string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, version)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Amazon advisories: %w", err)
	}
	return advisories, nil
}

func severityFromPriority(priority string) types.Severity {
	switch priority {
	case "low":
		return types.SeverityLow
	case "medium":
		return types.SeverityMedium
	case "important":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	default:
		return types.SeverityUnknown
	}
}
