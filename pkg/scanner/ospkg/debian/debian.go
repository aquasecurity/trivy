package debian

import (
	"strings"

	version "github.com/knqyf263/go-deb-version"

	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/pkg/scanner/utils"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/vulnsrc/debian"
	debianoval "github.com/knqyf263/trivy/pkg/vulnsrc/debian-oval"
)

type Scanner struct{}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Detect(osVer string, pkgs []analyzer.Package) ([]vulnerability.DetectedVulnerability, error) {
	log.Logger.Info("Detecting Debian vulnerabilities...")

	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}
	log.Logger.Debugf("debian: os version: %s", osVer)
	log.Logger.Debugf("debian: the number of packages: %s", len(pkgs))

	var vulns []vulnerability.DetectedVulnerability
	for _, pkg := range pkgs {
		if pkg.Type != analyzer.TypeSource {
			continue
		}
		advisories, err := debianoval.Get(osVer, pkg.Name)
		if err != nil {
			return nil, xerrors.Errorf("failed to get debian OVAL: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		installedVersion, err := version.NewVersion(installed)
		if err != nil {
			log.Logger.Debugf("failed to parse Debian installed package version: %w", err)
			continue
		}

		for _, adv := range advisories {
			fixedVersion, err := version.NewVersion(adv.FixedVersion)
			if err != nil {
				log.Logger.Debugf("failed to parse Debian package version: %w", err)
				continue
			}

			if installedVersion.LessThan(fixedVersion) {
				vuln := vulnerability.DetectedVulnerability{
					VulnerabilityID:  adv.VulnerabilityID,
					PkgName:          pkg.Name,
					InstalledVersion: installed,
					FixedVersion:     adv.FixedVersion,
				}
				vulns = append(vulns, vuln)
			}
		}
		advisories, err = debian.Get(osVer, pkg.Name)
		if err != nil {
			return nil, xerrors.Errorf("failed to get debian advisory: %w", err)
		}
		for _, adv := range advisories {
			vuln := vulnerability.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
			}
			vulns = append(vulns, vuln)
		}
	}
	return vulns, nil
}
