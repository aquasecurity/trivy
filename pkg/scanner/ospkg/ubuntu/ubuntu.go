package ubuntu

import (
	version "github.com/knqyf263/go-deb-version"
	"github.com/knqyf263/trivy/pkg/scanner/utils"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"
	"golang.org/x/xerrors"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/vulnsrc/ubuntu"
)

type Scanner struct{}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Detect(osVer string, pkgs []analyzer.Package) ([]vulnerability.DetectedVulnerability, error) {
	log.Logger.Info("Detecting Ubuntu vulnerabilities...")
	log.Logger.Debugf("ubuntu: os version: %s", osVer)
	log.Logger.Debugf("ubuntu: the number of packages: %s", len(pkgs))

	var vulns []vulnerability.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := ubuntu.Get(osVer, pkg.SrcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get Ubuntu advisories: %w", err)
		}

		installed := utils.FormatSrcVersion(pkg)
		installedVersion, err := version.NewVersion(installed)
		if err != nil {
			log.Logger.Debugf("failed to parse Ubuntu installed package version: %w", err)
			continue
		}

		for _, adv := range advisories {
			vuln := vulnerability.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
				FixedVersion:     adv.FixedVersion,
			}

			if adv.FixedVersion == "" {
				vulns = append(vulns, vuln)
				continue
			}

			fixedVersion, err := version.NewVersion(adv.FixedVersion)
			if err != nil {
				log.Logger.Debugf("failed to parse Ubuntu package version: %w", err)
				continue
			}

			if installedVersion.LessThan(fixedVersion) {
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}
