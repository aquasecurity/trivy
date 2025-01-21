package redhat

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	redhat "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
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

// Scanner implements the RedHat scanner
type Scanner struct {
	vs redhat.VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	return &Scanner{
		vs: redhat.NewVulnSrc(),
	}
}

// Detect scans and returns redhat vulnerabilities
func (s *Scanner) Detect(ctx context.Context, osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	osVer = osver.Major(osVer)
	log.InfoContext(ctx, "Detecting RHEL/CentOS vulnerabilities...", log.String("os_version", osVer),
		log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		if !isFromSupportedVendor(pkg) {
			log.DebugContext(ctx, "Skipping the package with unsupported vendor", log.String("package", pkg.Name))
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

	// Choose the latest fixed version for each CVE-ID (empty for unpatched vulns).
	// Take the single RHSA-ID with the latest fixed version (for patched vulns).
	uniqAdvisories := make(map[string]dbTypes.Advisory)
	for _, adv := range advisories {
		// If Arches for advisory are empty or pkg.Arch is "noarch", then any Arches are affected
		if len(adv.Arches) != 0 && pkg.Arch != "noarch" {
			if !slices.Contains(adv.Arches, pkg.Arch) {
				continue
			}
		}

		if a, ok := uniqAdvisories[adv.VulnerabilityID]; ok {
			if version.NewVersion(a.FixedVersion).LessThan(version.NewVersion(adv.FixedVersion)) {
				uniqAdvisories[adv.VulnerabilityID] = adv
			}
		} else {
			uniqAdvisories[adv.VulnerabilityID] = adv
		}
	}

	var vulns []types.DetectedVulnerability
	for _, adv := range uniqAdvisories {
		vuln := types.DetectedVulnerability{
			VulnerabilityID:  adv.VulnerabilityID,
			VendorIDs:        adv.VendorIDs, // Will be empty for unpatched vulnerabilities
			PkgID:            pkg.ID,
			PkgName:          pkg.Name,
			InstalledVersion: utils.FormatVersion(pkg),
			FixedVersion:     version.NewVersion(adv.FixedVersion).String(), // Will be empty for unpatched vulnerabilities
			PkgIdentifier:    pkg.Identifier,
			Status:           adv.Status,
			Layer:            pkg.Layer,
			SeveritySource:   vulnerability.RedHat,
			Vulnerability: dbTypes.Vulnerability{
				Severity: adv.Severity.String(),
			},
			Custom: adv.Custom,
		}

		// Keep unpatched and affected vulnerabilities
		if adv.FixedVersion == "" || version.NewVersion(vuln.InstalledVersion).LessThan(version.NewVersion(adv.FixedVersion)) {
			vulns = append(vulns, vuln)
		}
	}

	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].VulnerabilityID < vulns[j].VulnerabilityID
	})
	return vulns, nil
}

// IsSupportedVersion checks is OSFamily can be scanned with Redhat scanner
func (s *Scanner) IsSupportedVersion(ctx context.Context, osFamily ftypes.OSType, osVer string) bool {
	osVer = osver.Major(osVer)
	if osFamily == ftypes.CentOS {
		return osver.Supported(ctx, centosEOLDates, osFamily, osVer)
	}

	return osver.Supported(ctx, redhatEOLDates, osFamily, osVer)
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
