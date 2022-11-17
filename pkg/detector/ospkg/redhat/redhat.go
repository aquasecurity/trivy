package redhat

import (
	"fmt"
	"sort"
	"strings"
	"time"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ustrings "github.com/aquasecurity/trivy-db/pkg/utils/strings"
	redhat "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	defaultContentSets = map[string][]string{
		"6": {
			"rhel-6-server-rpms",
			"rhel-6-server-extras-rpms",
		},
		"7": {
			"rhel-7-server-rpms",
			"rhel-7-server-extras-rpms",
		},
		"8": {
			"rhel-8-for-x86_64-baseos-rpms",
			"rhel-8-for-x86_64-appstream-rpms",
		},
		"9": {
			"rhel-9-for-x86_64-baseos-rpms",
			"rhel-9-for-x86_64-appstream-rpms",
		},
	}
	redhatEOLDates = map[string]time.Time{
		"4": time.Date(2017, 5, 31, 23, 59, 59, 0, time.UTC),
		"5": time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC),
		"6": time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
		// N/A
		"7": time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC),
		"8": time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC),
		"9": time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC),
	}
	centosEOLDates = map[string]time.Time{
		"3": time.Date(2010, 10, 31, 23, 59, 59, 0, time.UTC),
		"4": time.Date(2012, 2, 29, 23, 59, 59, 0, time.UTC),
		"5": time.Date(2017, 3, 31, 23, 59, 59, 0, time.UTC),
		"6": time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC),
		"7": time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
		"8": time.Date(2021, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	excludedVendorsSuffix = []string{
		".remi",
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

// Scanner implements the RedHat scanner
type Scanner struct {
	vs redhat.VulnSrc
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
		vs:      redhat.NewVulnSrc(),
		options: o,
	}
}

// Detect scans and returns redhat vulnerabilities
func (s *Scanner) Detect(osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting RHEL/CentOS vulnerabilities...")
	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}
	log.Logger.Debugf("Red Hat: os version: %s", osVer)
	log.Logger.Debugf("Red Hat: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		if !isFromSupportedVendor(pkg) {
			log.Logger.Debugf("Skipping %s: unsupported vendor", pkg.Name)
			continue
		}

		detectedVulns, err := s.detect(osVer, pkg)
		if err != nil {
			return nil, xerrors.Errorf("redhat vulnerability detection error: %w", err)
		}
		vulns = append(vulns, detectedVulns...)
	}
	return vulns, nil
}

func (s *Scanner) detect(osVer string, pkg ftypes.Package) ([]types.DetectedVulnerability, error) {
	// For Red Hat OVAL v2 containing only binary package names
	pkgName := addModularNamespace(pkg.Name, pkg.Modularitylabel)

	var contentSets []string
	var nvr string
	if pkg.BuildInfo == nil {
		contentSets = defaultContentSets[osVer]
	} else {
		contentSets = pkg.BuildInfo.ContentSets
		nvr = fmt.Sprintf("%s-%s", pkg.BuildInfo.Nvr, pkg.BuildInfo.Arch)
	}

	advisories, err := s.vs.Get(pkgName, contentSets, []string{nvr})
	if err != nil {
		return nil, xerrors.Errorf("failed to get Red Hat advisories: %w", err)
	}

	installed := utils.FormatVersion(pkg)
	installedVersion := version.NewVersion(installed)

	uniqVulns := map[string]types.DetectedVulnerability{}
	for _, adv := range advisories {
		// if Arches for advisory is empty or pkg.Arch is "noarch", then any Arches are affected
		if len(adv.Arches) != 0 && pkg.Arch != "noarch" {
			if !slices.Contains(adv.Arches, pkg.Arch) {
				continue
			}
		}

		vulnID := adv.VulnerabilityID
		vuln := types.DetectedVulnerability{
			VulnerabilityID:  vulnID,
			PkgID:            pkg.ID,
			PkgName:          pkg.Name,
			InstalledVersion: utils.FormatVersion(pkg),
			Ref:              pkg.Ref,
			Layer:            pkg.Layer,
			SeveritySource:   vulnerability.RedHat,
			Vulnerability: dbTypes.Vulnerability{
				Severity: adv.Severity.String(),
			},
			Custom: adv.Custom,
		}

		// unpatched vulnerabilities
		if adv.FixedVersion == "" {
			// Red Hat may contain several advisories for the same vulnerability (RHSA advisories).
			// To avoid overwriting the fixed version by mistake, we should skip unpatched vulnerabilities if they were added earlier
			if _, ok := uniqVulns[vulnID]; !ok {
				uniqVulns[vulnID] = vuln
			}
			continue
		}

		// patched vulnerabilities
		fixedVersion := version.NewVersion(adv.FixedVersion)
		if installedVersion.LessThan(fixedVersion) {
			vuln.VendorIDs = adv.VendorIDs
			vuln.FixedVersion = fixedVersion.String()

			if v, ok := uniqVulns[vulnID]; ok {
				// In case two advisories resolve the same CVE-ID.
				// e.g. The first fix might be incomplete.
				v.VendorIDs = ustrings.Unique(append(v.VendorIDs, vuln.VendorIDs...))

				// The newer fixed version should be taken.
				if version.NewVersion(v.FixedVersion).LessThan(fixedVersion) {
					v.FixedVersion = vuln.FixedVersion
				}
				uniqVulns[vulnID] = v
			} else {
				uniqVulns[vulnID] = vuln
			}
		}
	}

	vulns := maps.Values(uniqVulns)
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].VulnerabilityID < vulns[j].VulnerabilityID
	})

	return vulns, nil
}

// IsSupportedVersion checks is OSFamily can be scanned with Redhat scanner
func (s *Scanner) IsSupportedVersion(osFamily, osVer string) bool {
	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}

	var eolDate time.Time
	var ok bool
	if osFamily == os.RedHat {
		eolDate, ok = redhatEOLDates[osVer]
	} else if osFamily == os.CentOS {
		eolDate, ok = centosEOLDates[osVer]
	}
	if !ok {
		log.Logger.Warnf("This OS version is not on the EOL list: %s %s", osFamily, osVer)
		return false
	}

	return s.clock.Now().Before(eolDate)
}

func isFromSupportedVendor(pkg ftypes.Package) bool {
	for _, suffix := range excludedVendorsSuffix {
		if strings.HasSuffix(pkg.Release, suffix) {
			return false
		}
	}
	return true
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
