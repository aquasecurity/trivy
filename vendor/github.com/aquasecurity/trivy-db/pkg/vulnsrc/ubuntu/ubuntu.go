package ubuntu

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/utils/strings"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	ubuntuDir      = "ubuntu"
	platformFormat = "ubuntu %s"
)

var (
	targetStatuses        = []string{"needed", "deferred", "released"}
	UbuntuReleasesMapping = map[string]string{
		"precise": "12.04",
		"quantal": "12.10",
		"raring":  "13.04",
		"saucy":   "13.10",
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
		"eoan":    "19.10",
		"focal":   "20.04",
		"groovy":  "20.10",
		"hirsute": "21.04",
		"impish":  "21.10",
	}

	source = types.DataSource{
		ID:   vulnerability.Ubuntu,
		Name: "Ubuntu CVE Tracker",
		URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
	}
)

type Option func(src *VulnSrc)

func WithCustomPut(put db.CustomPut) Option {
	return func(src *VulnSrc) {
		src.put = put
	}
}

type VulnSrc struct {
	put db.CustomPut
	dbc db.Operation
}

func NewVulnSrc(opts ...Option) VulnSrc {
	src := VulnSrc{
		put: defaultPut,
		dbc: db.Config{},
	}

	for _, o := range opts {
		o(&src)
	}

	return src
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", ubuntuDir)
	var cves []UbuntuCVE
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cve UbuntuCVE
		if err := json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("failed to decode Ubuntu JSON: %w", err)
		}
		cves = append(cves, cve)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Ubuntu walk: %w", err)
	}

	if err = vs.save(cves); err != nil {
		return xerrors.Errorf("error in Ubuntu save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(cves []UbuntuCVE) error {
	log.Println("Saving Ubuntu DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		err := vs.commit(tx, cves)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, cves []UbuntuCVE) error {
	for _, cve := range cves {
		if err := vs.put(vs.dbc, tx, cve); err != nil {
			return xerrors.Errorf("put error: %w", err)
		}
	}
	return nil
}

func (vs VulnSrc) Get(release string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Ubuntu advisories: %w", err)
	}
	return advisories, nil
}

func defaultPut(dbc db.Operation, tx *bolt.Tx, advisory interface{}) error {
	cve, ok := advisory.(UbuntuCVE)
	if !ok {
		return xerrors.New("unknown type")
	}

	for packageName, patch := range cve.Patches {
		pkgName := string(packageName)
		for release, status := range patch {
			if !strings.InSlice(status.Status, targetStatuses) {
				continue
			}
			osVersion, ok := UbuntuReleasesMapping[string(release)]
			if !ok {
				continue
			}
			platformName := fmt.Sprintf(platformFormat, osVersion)
			if err := dbc.PutDataSource(tx, platformName, source); err != nil {
				return xerrors.Errorf("failed to put data source: %w", err)
			}

			adv := types.Advisory{}
			if status.Status == "released" {
				adv.FixedVersion = status.Note
			}
			if err := dbc.PutAdvisoryDetail(tx, cve.Candidate, pkgName, []string{platformName}, adv); err != nil {
				return xerrors.Errorf("failed to save Ubuntu advisory: %w", err)
			}

			vuln := types.VulnerabilityDetail{
				Severity:    SeverityFromPriority(cve.Priority),
				References:  cve.References,
				Description: cve.Description,
			}
			if err := dbc.PutVulnerabilityDetail(tx, cve.Candidate, source.ID, vuln); err != nil {
				return xerrors.Errorf("failed to save Ubuntu vulnerability: %w", err)
			}

			// for optimization
			if err := dbc.PutVulnerabilityID(tx, cve.Candidate); err != nil {
				return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
			}
		}
	}

	return nil
}

// SeverityFromPriority converts Ubuntu priority into Trivy severity
func SeverityFromPriority(priority string) types.Severity {
	switch priority {
	case "untriaged":
		return types.SeverityUnknown
	case "negligible", "low":
		return types.SeverityLow
	case "medium":
		return types.SeverityMedium
	case "high":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	default:
		return types.SeverityUnknown
	}
}
