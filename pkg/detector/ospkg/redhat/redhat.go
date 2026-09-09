package redhat

import (
	"context"
	"fmt"
	"regexp"
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
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
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
		"7":  time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC),
		"8":  time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC),
		"9":  time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC),
		"10": time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC),
	}
	centosEOLDates = map[string]time.Time{
		"3": time.Date(2010, 10, 31, 23, 59, 59, 0, time.UTC),
		"4": time.Date(2012, 2, 29, 23, 59, 59, 0, time.UTC),
		"5": time.Date(2017, 3, 31, 23, 59, 59, 0, time.UTC),
		"6": time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC),
		"7": time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
		"8": time.Date(2021, 12, 31, 23, 59, 59, 0, time.UTC),
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

	// Clean content sets from generic suffixes (__8, __9, etc.)
	contentSets = cleanContentSets(contentSets)

	advisories, err := s.vs.Get(pkgName, contentSets, []string{nvr})
	if err != nil {
		return nil, xerrors.Errorf("failed to get Red Hat advisories: %w", err)
	}

	// Group advisories per CVE-ID, keeping every fixed version. Red Hat ships
	// one errata per minor release for the same CVE, so the advisories for a
	// CVE are compared against the installed package's own minor release: a
	// package already carrying that fix is not vulnerable just because a
	// newer minor rebuilt the package at a higher version (cf. #11199).
	uniqAdvisories := make(map[string]dbTypes.Advisory)
	fixedAdvisories := make(map[string][]dbTypes.Advisory)
	for _, adv := range advisories {
		// If Arches for advisory are empty or pkg.Arch is "noarch", then any Arches are affected
		if len(adv.Arches) != 0 && pkg.Arch != "noarch" {
			if !slices.Contains(adv.Arches, pkg.Arch) {
				continue
			}
		}

		if adv.FixedVersion == "" {
			// Unpatched entries only stand in when nothing fixes the CVE:
			// an entry with a fix always wins (cf. #8061).
			if _, ok := uniqAdvisories[adv.VulnerabilityID]; !ok {
				uniqAdvisories[adv.VulnerabilityID] = adv
			}
			continue
		}
		fixedAdvisories[adv.VulnerabilityID] = append(fixedAdvisories[adv.VulnerabilityID], adv)
	}

	installedVersion := utils.FormatVersion(pkg)
	installedMinor := rhelMinor(installedVersion)
	for id, advs := range fixedAdvisories {
		candidates := advs
		if installedMinor != "" {
			var scoped []dbTypes.Advisory
			for _, adv := range advs {
				if rhelMinor(adv.FixedVersion) == installedMinor {
					scoped = append(scoped, adv)
				}
			}
			// Fall back to every fixed version when the installed minor has
			// no advisory of its own: same as the old highest-wins behavior,
			// so nothing new is ever missed.
			if len(scoped) > 0 {
				candidates = scoped
			}
		}
		// Take the single RHSA-ID with the latest fixed version.
		winner := candidates[0]
		for _, adv := range candidates[1:] {
			if version.NewVersion(winner.FixedVersion).LessThan(version.NewVersion(adv.FixedVersion)) {
				winner = adv
			}
		}
		uniqAdvisories[id] = winner
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

// Match the minor release marker Red Hat stamps into RPM release strings
// (e.g. "18.el9_7.2" carries minor "7"), but not bare major markers like
// "100.el9", EUS suffixes aside.
var rhelMinorReleasePattern = regexp.MustCompile(`\.el\d+_(\d+)`)

// rhelMinor returns the RHEL minor release embedded in an EVR string
// (e.g. "0:2.68.4-18.el9_7.2" => "7"), or "" when there is no minor marker.
func rhelMinor(evr string) string {
	rel := evr
	if i := strings.LastIndex(evr, "-"); i >= 0 {
		rel = evr[i+1:]
	}
	m := rhelMinorReleasePattern.FindStringSubmatch(rel)
	if m == nil {
		return ""
	}
	return m[1]
}

// Match generic version suffixes like "__8", "__9", "__10", but preserve EUS suffixes like "__9_DOT_2".
// Examples:
//   - Matches: "repo__8", "repo__10"
//   - Does not match: "repo__9_DOT_2", "repo__10_DOT_1"
var genericSuffixPattern = regexp.MustCompile(`__\d+$`)

// cleanContentSets removes generic suffixes like "__8" from content sets.
// These are Red Hat image build artifacts and not valid repository names.
// Examples:
//
//	Input:  []string{"repo__8", "repo__9_DOT_2", "repo__10"}
//	Output: []string{"repo", "repo__9_DOT_2", "repo"}
//
// cf. https://github.com/aquasecurity/trivy-db/issues/435
func cleanContentSets(contentSets []string) []string {
	return xslices.Map(contentSets, func(cs string) string {
		return genericSuffixPattern.ReplaceAllString(cs, "")
	})
}
