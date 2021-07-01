package alpine

import (
	"strings"
	"time"

	version "github.com/knqyf263/go-apk-version"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	eolDates = map[string]time.Time{
		"2.0":  time.Date(2012, 4, 1, 23, 59, 59, 0, time.UTC),
		"2.1":  time.Date(2012, 11, 1, 23, 59, 59, 0, time.UTC),
		"2.2":  time.Date(2013, 5, 1, 23, 59, 59, 0, time.UTC),
		"2.3":  time.Date(2013, 11, 1, 23, 59, 59, 0, time.UTC),
		"2.4":  time.Date(2014, 5, 1, 23, 59, 59, 0, time.UTC),
		"2.5":  time.Date(2014, 11, 1, 23, 59, 59, 0, time.UTC),
		"2.6":  time.Date(2015, 5, 1, 23, 59, 59, 0, time.UTC),
		"2.7":  time.Date(2015, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.0":  time.Date(2016, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.1":  time.Date(2016, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.2":  time.Date(2017, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.3":  time.Date(2017, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.4":  time.Date(2018, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.5":  time.Date(2018, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.6":  time.Date(2019, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.7":  time.Date(2019, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.8":  time.Date(2020, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.9":  time.Date(2020, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.10": time.Date(2021, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.11": time.Date(2021, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.12": time.Date(2022, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.13": time.Date(2022, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.14": time.Date(2023, 5, 1, 23, 59, 59, 0, time.UTC),
	}
)

// Scanner implements the Alpine scanner
type Scanner struct {
	vs dbTypes.VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	return &Scanner{
		vs: alpine.NewVulnSrc(),
	}
}

// Detect vulnerabilities in package using Alpine scanner
func (s *Scanner) Detect(osVer string, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting Alpine vulnerabilities...")
	if strings.Count(osVer, ".") > 1 {
		osVer = osVer[:strings.LastIndex(osVer, ".")]
	}
	log.Logger.Debugf("alpine: os version: %s", osVer)
	log.Logger.Debugf("alpine: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(osVer, pkg.SrcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get alpine advisories: %w", err)
		}

		installed := utils.FormatSrcVersion(pkg)
		installedVersion, err := version.NewVersion(installed)
		if err != nil {
			log.Logger.Debugf("failed to parse Alpine Linux installed package version: %s", err)
			continue
		}

		for _, adv := range advisories {
			fixedVersion, err := version.NewVersion(adv.FixedVersion)
			if err != nil {
				log.Logger.Debugf("failed to parse Alpine Linux fixed version: %s", err)
				continue
			}
			if installedVersion.LessThan(fixedVersion) {
				vuln := types.DetectedVulnerability{
					VulnerabilityID:  adv.VulnerabilityID,
					PkgName:          pkg.Name,
					InstalledVersion: installed,
					FixedVersion:     adv.FixedVersion,
					Layer:            pkg.Layer,
				}
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

// IsSupportedVersion checks the OSFamily can be scanned using Alpine scanner
func (s *Scanner) IsSupportedVersion(osFamily, osVer string) bool {
	now := time.Now()
	return s.isSupportedVersion(now, osFamily, osVer)
}

func (s *Scanner) isSupportedVersion(now time.Time, osFamily, osVer string) bool {
	if strings.Count(osVer, ".") > 1 {
		osVer = osVer[:strings.LastIndex(osVer, ".")]
	}

	eol, ok := eolDates[osVer]
	if !ok {
		log.Logger.Warnf("This OS version is not on the EOL list: %s %s", osFamily, osVer)
		return false
	}
	return now.Before(eol)
}
