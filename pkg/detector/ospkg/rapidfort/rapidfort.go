package rapidfort

import (
	"cmp"
	"context"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/rapidfort"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/set"
	"github.com/aquasecurity/trivy/pkg/types"
)

// rpmDistTagRe matches an RPM %{dist} tag and its trailing digits. A release may
// contain more than one el/fc/rf substring (e.g. ".rfc3339"), so rpmDistTag uses
// the last match — the dist tag is the trailing element of the release.
//
//	"7.76.1-26.el9_3.3" → el/9    "7.76.1-26.fc43" → fc/43    "7.76.1-26.rf1" → rf/1
//	"8.5.0-1.amzn2023"  → amzn/2023
var rpmDistTagRe = regexp.MustCompile(`\.(el|fc|rf|amzn)(\d*)`)

// rpmDistTag returns the RPM dist tag and its trailing digits from a version
// string, or ("", "") for an untagged RPM.
func rpmDistTag(ver string) (tag, num string) {
	m := rpmDistTagRe.FindAllStringSubmatch(ver, -1)
	if len(m) == 0 {
		return "", ""
	}
	last := m[len(m)-1]
	return last[1], last[2]
}

// rfMarkerRe matches a RapidFort rebuild marker in a dpkg version; a stock
// distribution build never carries one. Three parts, left to right:
//
//	[0-9+~.]            Separator before it, so "rf" counts only as its own
//	                    revision element, never inside a word ("1.0-1surf1").
//	rf(?:ubu[a-z]*)?    The marker: bare "rf", or "ubu" plus an optional
//	                    variant suffix ("rfubu", "rfubuntu", "rfubujl").
//	(?:[^a-z]|$)        Digit, separator or end after it, so a spelling with
//	                    no "ubu" cannot match on its "rf" prefix ("rfdebian").
//
//	match:    0:2.46-10rfubu  0:3.3.3-1rfubuntu0.24.04.1  0:2.43-14.rf
//	          8.18.0-11rfubujl
//	no match: 7.81.0-1ubuntu1.15  1.0-1surf1  0:3.2.1-4rfdebian
var rfMarkerRe = regexp.MustCompile(`[0-9+~.]rf(?:ubu[a-z]*)?(?:[^a-z]|$)`)

// dpkgHasRfMarker reports whether a Debian/Ubuntu version string carries a
// RapidFort rebuild marker — the same signal the feed annotator writes as the
// "rf" range identifier, so the routing decision here matches the DB build.
func dpkgHasRfMarker(ver string) bool {
	return rfMarkerRe.MatchString(ver)
}

// getters is package-level because a getter is not tied to a scanner: the
// release is passed at Get time, so one getter serves both "rapidfort ubuntu
// 22.04" and the family-level "rapidfort ubuntu".
var getters = map[ecosystem.Type]rapidfort.VulnSrcGetter{
	ecosystem.Ubuntu:      rapidfort.NewVulnSrcGetter(ecosystem.Ubuntu),
	ecosystem.Debian:      rapidfort.NewVulnSrcGetter(ecosystem.Debian),
	ecosystem.Alpine:      rapidfort.NewVulnSrcGetter(ecosystem.Alpine),
	ecosystem.RedHat:      rapidfort.NewVulnSrcGetter(ecosystem.RedHat),
	ecosystem.OracleLinux: rapidfort.NewVulnSrcGetter(ecosystem.OracleLinux),
	ecosystem.Rocky:       rapidfort.NewVulnSrcGetter(ecosystem.Rocky),
	ecosystem.AlmaLinux:   rapidfort.NewVulnSrcGetter(ecosystem.AlmaLinux),
	ecosystem.AmazonLinux: rapidfort.NewVulnSrcGetter(ecosystem.AmazonLinux),
	ecosystem.Fedora:      rapidfort.NewVulnSrcGetter(ecosystem.Fedora),
}

// Scanner detects vulnerabilities for RapidFort curated images by querying
// the RapidFort advisory data that was ingested by trivy-db.
type Scanner struct {
	baseOS   ftypes.OSType
	comparer version.Comparer
	// versionTrimmer normalizes the installed OS version to the granularity
	// that RapidFort advisories are keyed on (e.g. "22.04.1" → "22.04" for Ubuntu,
	// "9.2" → "9" for RedHat).
	versionTrimmer func(string) string
	logger         *log.Logger
}

// NewScanner creates a RapidFort Scanner for the given base OS type.
func NewScanner(baseOS ftypes.OSType) *Scanner {
	s := &Scanner{
		baseOS: baseOS,
		logger: log.WithPrefix("rapidfort"),
	}

	switch baseOS {
	case ftypes.Ubuntu:
		s.comparer = version.NewDEBComparer()
		s.versionTrimmer = version.Minor // "22.04.1" → "22.04"
	case ftypes.Debian:
		s.comparer = version.NewDEBComparer()
		s.versionTrimmer = version.Major // "12.15" → "12"
	case ftypes.Alpine:
		s.comparer = version.NewAPKComparer()
		s.versionTrimmer = version.Minor // "3.17.2" → "3.17"
	case ftypes.RedHat, ftypes.Oracle, ftypes.Rocky, ftypes.Alma, ftypes.Amazon:
		s.comparer = version.NewRPMComparer()
		s.versionTrimmer = version.Major // "9.2" → "9"; Amazon's "2023" is already a major
	default:
		// Scanners are only created for the families in familyEcosystems; the
		// DEB comparer + minor trimmer here is a safe placeholder for any direct
		// caller, whose packages route to no ecosystem anyway.
		s.comparer = version.NewDEBComparer()
		s.versionTrimmer = version.Minor
	}

	return s
}

// familyEcosystems maps each OS RapidFort curates to the ecosystem its
// advisories are bucketed under. The RapidFort vulnsrc in trivy-db picks the
// same ecosystem per OS when it writes those buckets, so the two mappings have
// to stay in step.
var familyEcosystems = map[ftypes.OSType]ecosystem.Type{
	ftypes.Ubuntu: ecosystem.Ubuntu,
	ftypes.Debian: ecosystem.Debian,
	ftypes.Alpine: ecosystem.Alpine,
	ftypes.RedHat: ecosystem.RedHat,
	ftypes.Oracle: ecosystem.OracleLinux,
	ftypes.Rocky:  ecosystem.Rocky,
	ftypes.Alma:   ecosystem.AlmaLinux,
	ftypes.Amazon: ecosystem.AmazonLinux,
}

// route picks the (ecosystem, release) pair whose bucket the installed package
// belongs in. RapidFort's own rebuilds are not tied to a distribution release,
// so they drop it and land in the family-level bucket of their ecosystem — one
// per feed, which is what keeps an RPM range away from the dpkg comparator.
func (s *Scanner) route(installedVer, osVer string) (ecosystem.Type, string) {
	eco, ok := familyEcosystems[s.baseOS]
	if !ok {
		// Unsupported base OS: no getter matches the empty ecosystem.
		return "", osVer
	}

	switch s.baseOS {
	// The dpkg families carry the rebuild marker in the package revision;
	// their distribution packages have no tag to route on.
	case ftypes.Ubuntu, ftypes.Debian:
		if dpkgHasRfMarker(installedVer) {
			return eco, ""
		}
		return eco, osVer
	case ftypes.Alpine:
		return eco, osVer
	}

	// The RPM families: the dist tag names the release, and for "fc" the
	// distribution too.
	switch tag, num := rpmDistTag(installedVer); tag {
	case "fc":
		return ecosystem.Fedora, num
	case "rf":
		return eco, ""
	case "el", "amzn":
		// Use the package's own dist-tag major, not osVer: an .el8
		// package inside a RHEL 9 image belongs to the Red Hat 8 bucket.
		// cmp.Or supplies osVer when the tag carries no major at all
		// ("7.76.1-26.el"), since that names no release of its own.
		return eco, cmp.Or(num, osVer)
	default:
		// An untagged RPM names no distribution, so it is treated as a build of
		// the image's own release.
		return eco, osVer
	}
}

// Detect queries the RapidFort advisory DB for vulnerabilities in the given packages.
func (s *Scanner) Detect(ctx context.Context, osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	osVer = s.versionTrimmer(osVer)
	log.InfoContext(ctx, "Detecting RapidFort advisories...",
		log.String("os", string(s.baseOS)),
		log.String("version", osVer),
		log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		// An RPM without SOURCERPM carries no source name or version at all, so
		// both fall back to the binary package.
		srcName := cmp.Or(pkg.SrcName, pkg.Name)
		installedVer := cmp.Or(utils.FormatSrcVersion(pkg), utils.FormatVersion(pkg))

		eco, release := s.route(installedVer, osVer)
		vs, ok := getters[eco]
		if !ok {
			continue // RapidFort ships no buckets for this ecosystem, so the package goes unscanned
		}

		advisories, err := vs.Get(db.GetParams{
			Release: release,
			PkgName: srcName,
		})
		if err != nil {
			return nil, xerrors.Errorf("failed to get RapidFort advisories for %s: %w", srcName, err)
		}

		// Some advisory files key entries by the binary package name rather
		// than the SRPM name, so fall back to the binary name when the two
		// differ. SRPM entries win on collision.
		if pkg.Name != srcName {
			binAdvisories, err := vs.Get(db.GetParams{
				Release: release,
				PkgName: pkg.Name,
			})
			if err != nil {
				return nil, xerrors.Errorf("failed to get RapidFort advisories for %s: %w", pkg.Name, err)
			}
			if len(binAdvisories) > 0 {
				seen := set.New[string]()
				for _, adv := range advisories {
					seen.Append(adv.VulnerabilityID)
				}
				for _, adv := range binAdvisories {
					if seen.Contains(adv.VulnerabilityID) {
						continue
					}
					seen.Append(adv.VulnerabilityID)
					advisories = append(advisories, adv)
				}
			}
		}

		for _, adv := range advisories {
			if !s.isVulnerable(ctx, installedVer, adv) {
				continue
			}

			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgID:            pkg.ID,
				PkgName:          pkg.Name,
				InstalledVersion: utils.FormatVersion(pkg),
				FixedVersion:     strings.Join(adv.PatchedVersions, ", "),
				Layer:            pkg.Layer,
				PkgIdentifier:    pkg.Identifier,
				DataSource:       adv.DataSource,
			}

			if adv.Severity != dbTypes.SeverityUnknown {
				vuln.Vulnerability = dbTypes.Vulnerability{
					Severity: adv.Severity.String(),
				}
				vuln.SeveritySource = adv.DataSource.ID
			}

			vulns = append(vulns, vuln)
		}
	}

	s.logger.DebugContext(ctx, "RapidFort scan complete",
		log.String("os", string(s.baseOS)),
		log.Int("total_vulns", len(vulns)))

	return vulns, nil
}

func (s *Scanner) isVulnerable(ctx context.Context, installedVersion string, adv dbTypes.Advisory) bool {
	if installedVersion == "" {
		return false
	}

	// An empty range list means "all versions are vulnerable" (the advisory
	// exists but has no fixed version yet).
	if len(adv.VulnerableVersions) == 0 {
		return true
	}

	return s.checkConstraints(ctx, installedVersion, adv.VulnerableVersions)
}

func (s *Scanner) checkConstraints(ctx context.Context, installedVersion string, constraintsStr []string) bool {
	for _, constraintStr := range constraintsStr {
		constraints, err := version.NewConstraints(constraintStr, s.comparer)
		if err != nil {
			s.logger.DebugContext(ctx, "Failed to parse version constraints",
				log.String("installed", installedVersion),
				log.String("constraint", constraintStr),
				log.Err(err))
			continue
		}

		satisfied, err := constraints.Check(installedVersion)
		if err != nil {
			s.logger.DebugContext(ctx, "Failed to check version constraints",
				log.String("installed", installedVersion),
				log.String("constraint", constraintStr),
				log.Err(err))
			continue
		}

		if satisfied {
			return true
		}
	}
	return false
}

// IsSupportedVersion never rejects a scan on OS version alone: RapidFort
// curates advisories for EOL distributions too.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}

var _ driver.PackageFilter = (*Scanner)(nil)

// FilterPackages keeps every package. RapidFort curated images ship patched
// third-party packages (MariaDB, Docker, …) that RapidFort's own feed covers,
// so the default third-party drop would strip real advisory targets.
func (s *Scanner) FilterPackages(_ context.Context, pkgs []ftypes.Package) []ftypes.Package {
	return pkgs
}
