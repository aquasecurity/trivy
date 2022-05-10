package photon

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const (
	photonDir      = "photon"
	platformFormat = "Photon OS %s"
)

var source = types.DataSource{
	ID:   vulnerability.Photon,
	Name: "Photon OS CVE metadata",
	URL:  "https://packages.vmware.com/photon/photon_cve_metadata/",
}

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
	rootDir := filepath.Join(dir, "vuln-list", photonDir)

	var cves []PhotonCVE
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cve PhotonCVE
		if err := json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("failed to decode Photon JSON: %w", err)
		}
		cves = append(cves, cve)

		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Photon walk: %w", err)
	}

	if err = vs.save(cves); err != nil {
		return xerrors.Errorf("unable to save Photon advisories: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(cves []PhotonCVE) error {
	log.Println("Saving Photon DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, cves)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}

	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, cves []PhotonCVE) error {
	for _, cve := range cves {
		platformName := fmt.Sprintf(platformFormat, cve.OSVersion)
		if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}

		advisory := types.Advisory{
			FixedVersion: cve.ResVer,
		}
		if err := vs.dbc.PutAdvisoryDetail(tx, cve.CveID, cve.Pkg, []string{platformName}, advisory); err != nil {
			return xerrors.Errorf("failed to save Photon advisory: %w", err)
		}

		vuln := types.VulnerabilityDetail{
			// Photon uses CVSS Version 3.X
			CvssScoreV3: cve.CveScore,
		}
		if err := vs.dbc.PutVulnerabilityDetail(tx, cve.CveID, source.ID, vuln); err != nil {
			return xerrors.Errorf("failed to save Photon vulnerability detail: %w", err)
		}

		// for optimization
		if err := vs.dbc.PutVulnerabilityID(tx, cve.CveID); err != nil {
			return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
		}
	}
	return nil
}

func (vs VulnSrc) Get(release string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Photon advisories: %w", err)
	}
	return advisories, nil
}
