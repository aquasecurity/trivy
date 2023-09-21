package suse

import (
	"time"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	susecvrf "github.com/aquasecurity/trivy-db/pkg/vulnsrc/suse-cvrf"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
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
		"12.4": time.Date(2020, 6, 30, 23, 59, 59, 0, time.UTC),
		"12.5": time.Date(2024, 10, 31, 23, 59, 59, 0, time.UTC),
		"15":   time.Date(2019, 12, 31, 23, 59, 59, 0, time.UTC),
		"15.1": time.Date(2021, 1, 31, 23, 59, 59, 0, time.UTC),
		"15.2": time.Date(2021, 12, 31, 23, 59, 59, 0, time.UTC),
		"15.3": time.Date(2022, 12, 31, 23, 59, 59, 0, time.UTC),
		"15.4": time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC),
		"15.5": time.Date(2028, 12, 31, 23, 59, 59, 0, time.UTC),
		// 6 months after SLES 15 SP7 release
		//"15.6": time.Date(2028, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	opensuseEolDates = map[string]time.Time{
		// Source: https://en.opensuse.org/Lifetime
		"42.1": time.Date(2017, 5, 17, 23, 59, 59, 0, time.UTC),
		"42.2": time.Date(2018, 1, 26, 23, 59, 59, 0, time.UTC),
		"42.3": time.Date(2019, 6, 30, 23, 59, 59, 0, time.UTC),
		"15.0": time.Date(2019, 12, 3, 23, 59, 59, 0, time.UTC),
		"15.1": time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC),
		"15.2": time.Date(2021, 11, 30, 23, 59, 59, 0, time.UTC),
		"15.3": time.Date(2022, 11, 30, 23, 59, 59, 0, time.UTC),
		"15.4": time.Date(2023, 11, 30, 23, 59, 59, 0, time.UTC),
		"15.5": time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
	}
)

type options struct {
	clock clock.Clock
}

type option func(*options)

func WithClock(clock clock.Clock) option {
	return func(opts *options) {
		opts.clock = clock
	}
}

// Type defines SUSE type
type Type int

const (
	// SUSEEnterpriseLinux is Linux Enterprise version
	SUSEEnterpriseLinux Type = iota
	// OpenSUSE for open versions
	OpenSUSE
)

// Scanner implements the SUSE scanner
type Scanner struct {
	vs susecvrf.VulnSrc
	*options
}

// NewScanner is the factory method for Scanner
func NewScanner(t Type, opts ...option) *Scanner {
	o := &options{
		clock: clock.RealClock{},
	}

	for _, opt := range opts {
		opt(o)
	}

	switch t {
	case SUSEEnterpriseLinux:
		return &Scanner{
			vs:      susecvrf.NewVulnSrc(susecvrf.SUSEEnterpriseLinux),
			options: o,
		}
	case OpenSUSE:
		return &Scanner{
			vs:      susecvrf.NewVulnSrc(susecvrf.OpenSUSE),
			options: o,
		}
	}
	return nil
}

// Detect scans and returns the vulnerabilities
func (s *Scanner) Detect(osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting SUSE vulnerabilities...")
	log.Logger.Debugf("SUSE: os version: %s", osVer)
	log.Logger.Debugf("SUSE: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(osVer, pkg.Name)
		if err != nil {
			return nil, xerrors.Errorf("failed to get SUSE advisory: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		installedVersion := version.NewVersion(installed)
		for _, adv := range advisories {
			fixedVersion := version.NewVersion(adv.FixedVersion)
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgID:            pkg.ID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
				PkgRef:           pkg.Ref,
				Layer:            pkg.Layer,
				Custom:           adv.Custom,
				DataSource:       adv.DataSource,
			}
			if installedVersion.LessThan(fixedVersion) {
				vuln.FixedVersion = adv.FixedVersion
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

// IsSupportedVersion checks if OSFamily can be scanned using SUSE scanner
func (s *Scanner) IsSupportedVersion(osFamily ftypes.OSType, osVer string) bool {
	var eolDate time.Time
	var ok bool

	if osFamily == ftypes.SLES {
		eolDate, ok = slesEolDates[osVer]
	} else if osFamily == ftypes.OpenSUSELeap {
		eolDate, ok = opensuseEolDates[osVer]
	}

	if !ok {
		log.Logger.Warnf("This OS version is not on the EOL list: %s %s", osFamily, osVer)
		return false
	}

	return s.clock.Now().Before(eolDate)
}
