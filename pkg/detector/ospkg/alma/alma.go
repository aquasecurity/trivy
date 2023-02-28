package alma

import (
	"strings"
	"time"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alma"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	eolDates = map[string]time.Time{
		// Source:
		// https://endoflife.date/almalinux
		"8": time.Date(2029, 3, 1, 23, 59, 59, 0, time.UTC),
		"9": time.Date(2032, 5, 31, 23, 59, 59, 0, time.UTC),
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

// Scanner implements the AlmaLinux scanner
type Scanner struct {
	vs *alma.VulnSrc
	*options
}

// NewScanner is the factory method for Scanner
func NewScanner(opts ...option) *Scanner {
	o := &options{
		clock: clock.RealClock{},
	}

	for _, opt := range opts {
		opt(o)
	}
	return &Scanner{
		vs:      alma.NewVulnSrc(),
		options: o,
	}
}

// Detect vulnerabilities in package using AlmaLinux scanner
func (s *Scanner) Detect(osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting AlmaLinux vulnerabilities...")
	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}
	log.Logger.Debugf("AlmaLinux: os version: %s", osVer)
	log.Logger.Debugf("AlmaLinux: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	var skipPkgs []string
	for _, pkg := range pkgs {
		if strings.Contains(pkg.Release, ".module_el") && pkg.Modularitylabel == "" {
			skipPkgs = append(skipPkgs, pkg.Name)
			continue
		}
		pkgName := addModularNamespace(pkg.Name, pkg.Modularitylabel)
		advisories, err := s.vs.Get(osVer, pkgName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get AlmaLinux advisories: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		installedVersion := version.NewVersion(installed)

		for _, adv := range advisories {
			fixedVersion := version.NewVersion(adv.FixedVersion)
			if installedVersion.LessThan(fixedVersion) {
				vuln := types.DetectedVulnerability{
					VulnerabilityID:  adv.VulnerabilityID,
					PkgID:            pkg.ID,
					PkgName:          pkg.Name,
					InstalledVersion: installed,
					FixedVersion:     fixedVersion.String(),
					Ref:              pkg.Ref,
					Layer:            pkg.Layer,
					DataSource:       adv.DataSource,
					Custom:           adv.Custom,
				}
				vulns = append(vulns, vuln)
			}
		}
	}
	if len(skipPkgs) > 0 {
		log.Logger.Infof("Skipped detection of these packages: %q because modular packages cannot be detected correctly due to a bug in AlmaLinux. See also: https://bugs.almalinux.org/view.php?id=173", skipPkgs)
	}

	return vulns, nil
}

// IsSupportedVersion checks the OSFamily can be scanned using AlmaLinux scanner
func (s *Scanner) IsSupportedVersion(osFamily, osVer string) bool {
	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}

	eol, ok := eolDates[osVer]
	if !ok {
		log.Logger.Warnf("This OS version is not on the EOL list: %s %s", osFamily, osVer)
		return false
	}

	return s.clock.Now().Before(eol)
}

func addModularNamespace(name, label string) string {
	// e.g. npm, nodejs:12:8030020201124152102:229f0a1c => nodejs:12::npm
	var count int
	for i, r := range label {
		if r == ':' {
			count++
		}
		if count == 2 {
			return label[:i] + "::" + name
		}
	}
	return name
}
