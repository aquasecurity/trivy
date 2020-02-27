package photon

import (
	"time"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/photon"
	version "github.com/knqyf263/go-rpm-version"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"

	"k8s.io/utils/clock"
)

var (
	eolDates = map[string]time.Time{}
)

type Scanner struct {
	vs    dbTypes.VulnSrc
	clock clock.Clock
}

func NewScanner() *Scanner {
	return &Scanner{
		vs:    photon.NewVulnSrc(),
		clock: clock.RealClock{},
	}
}

func (s *Scanner) Detect(osVer string, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting Photon Linux vulnerabilities...")
	log.Logger.Debugf("Photon Linux: os version: %s", osVer)
	log.Logger.Debugf("Photon Linux: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(osVer, pkg.SrcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get Photon Linux advisory: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		installedVersion := version.NewVersion(installed)
		for _, adv := range advisories {
			fixedVersion := version.NewVersion(adv.FixedVersion)
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
			}
			if installedVersion.LessThan(fixedVersion) {
				vuln.FixedVersion = adv.FixedVersion
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

func (s *Scanner) IsSupportedVersion(osFamily, osVer string) bool {
	return true
}
