package suse

import (
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/fanal/analyzer"
	fos "github.com/aquasecurity/fanal/analyzer/os"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	suseoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/suse-oval"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"
)

var (
	slesEolDates = map[string]time.Time{
		// Source: https://www.suse.com/lifecycle/
		"10":   time.Date(2007, 12, 31, 23, 59, 59, 0, time.UTC),
		"10.1": time.Date(2008, 11, 30, 23, 59, 59, 0, time.UTC),
		"10.2": time.Date(2010, 4, 11, 23, 59, 59, 0, time.UTC),
		"10.3": time.Date(2011, 10, 11, 23, 59, 59, 0, time.UTC),
		"10.4": time.Date(2013, 7, 31, 23, 59, 59, 0, time.UTC),
		"11":   time.Date(2010, 12, 31, 23, 59, 59, 0, time.UTC),
		"11.1": time.Date(2012, 8, 31, 23, 59, 59, 0, time.UTC),
		"11.2": time.Date(2014, 1, 31, 23, 59, 59, 0, time.UTC),
		"11.3": time.Date(2016, 1, 31, 23, 59, 59, 0, time.UTC),
		"11.4": time.Date(2019, 3, 31, 23, 59, 59, 0, time.UTC),
		"12":   time.Date(2016, 6, 30, 23, 59, 59, 0, time.UTC),
		"12.1": time.Date(2017, 5, 31, 23, 59, 59, 0, time.UTC),
		"12.2": time.Date(2018, 3, 31, 23, 59, 59, 0, time.UTC),
		"12.3": time.Date(2019, 1, 30, 23, 59, 59, 0, time.UTC),
		// 6 months after SLES12 SP5 release
		// "12.4": time.Date(2024, 10, 31, 23, 59, 59, 0, time.UTC),
		"15": time.Date(2019, 12, 31, 23, 59, 59, 0, time.UTC),
		// 6 months after SLES 15 SP2 release
		// "15.1":   time.Date(2028, 7, 31, 23, 59, 59, 0, time.UTC),
	}

	opensuseEolDates = map[string]time.Time{
		// Source: https://en.opensuse.org/Lifetime
		"42.1": time.Date(2017, 5, 17, 23, 59, 59, 0, time.UTC),
		"42.2": time.Date(2018, 1, 26, 23, 59, 59, 0, time.UTC),
		"42.3": time.Date(2019, 6, 30, 23, 59, 59, 0, time.UTC),
		"15.0": time.Date(2019, 12, 3, 23, 59, 59, 0, time.UTC),
		"15.1": time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC),
		"15.2": time.Date(2021, 11, 30, 23, 59, 59, 0, time.UTC),
	}
)

type Scanner struct {
	vs     dbTypes.VulnSrc
	clock  clock.Clock
	family string
}

func NewScanner(family string) *Scanner {
	return &Scanner{
		vs:     suseoval.NewVulnSrc(),
		clock:  clock.RealClock{},
		family: family,
	}
}

func (s *Scanner) Detect(osVer string, pkgs []analyzer.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting SUSE vulnerabilities...")

	log.Logger.Debugf("SUSE: os version: %s", osVer)
	log.Logger.Debugf("SUSE: the number of packages: %d", len(pkgs))

	DBPrefix := ""
	switch s.family {
	case fos.SLES:
		DBPrefix = "SUSE Enterprise Linux "
		if strings.Count(osVer, ".") > 0 {
			osVer = osVer[:strings.Index(osVer, ".")]
		}
	case fos.OpenSUSELeap:
		DBPrefix = "OpenSUSE Leap "
	default:
		return nil, xerrors.New("unsupported SUSE family")
	}

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(DBPrefix+osVer, pkg.SrcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get SUSE advisory: %w", err)
		}
		fmt.Println(advisories)

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
	var eolDate time.Time
	var ok bool

	if osFamily == fos.SLES {
		eolDate, ok = slesEolDates[osVer]
	} else if osFamily == fos.OpenSUSELeap {
		eolDate, ok = opensuseEolDates[osVer]
	}

	if !ok {
		log.Logger.Warnf("This OS version is not on the EOL list: %s %s", osFamily, osVer)
		return false
	}

	return s.clock.Now().Before(eolDate)
}
