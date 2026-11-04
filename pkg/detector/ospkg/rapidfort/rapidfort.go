package rapidfort

import (
	"cmp"
	"context"
	"strings"
	"unicode"

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

// rpmDistTag returns the RPM dist tag and its trailing digits from the
// release part of a version string, or ("", "") for an untagged RPM. Only
// the release (after the first "-") is scanned, so an "rf" fragment that
// shows up in the upstream version is not misread as a dist tag. An "rf"
// element wins immediately when present: trivy-db routes rf-identified
// ranges to the family rebuild bucket regardless of any secondary dist tag,
// so a ".rf.fc43" package is an rf rebuild, not a Fedora one. For el / fc
// / amzn, the last matching element wins — multi-tagged releases like
// ".el8.fc43" put the real target distribution at the trailing element.
func rpmDistTag(ver string) (tag, num string) {
	_, release, _ := strings.Cut(ver, "-")
	for elem := range strings.SplitSeq(release, ".") {
		t, n, ok := parseDistTag(elem)
		if !ok {
			continue
		}
		if t == "rf" {
			return t, n
		}
		tag, num = t, n
	}
	return tag, num
}

// parseDistTag parses one release element against the four known tags.
// For el / fc / amzn, a bare tag ("el") or a tag pinned by a non-empty
// release number ("el10uek" → el/10) counts; a letters-only suffix with
// no number ("elastic", "fcgi") does not, since the tag has to be the
// element's leading identifier and not a substring that happens to open
// with the tag letters. For rf, any trailing letters must themselves be
// a distro code — empty after stripping letters — so "rf", "rf1" and
// "rfal" count but a date fragment like "rfc3339" does not.
func parseDistTag(elem string) (tag, num string, ok bool) {
	for _, t := range []string{"rf", "amzn", "el", "fc"} {
		rest, found := strings.CutPrefix(elem, t)
		if !found {
			continue
		}
		suffix := strings.TrimLeftFunc(rest, unicode.IsDigit)
		num = strings.TrimSuffix(rest, suffix)
		if t == "rf" {
			return t, num, strings.TrimFunc(suffix, unicode.IsLetter) == ""
		}
		return t, num, suffix == "" || num != ""
	}
	return "", "", false
}

// dpkgHasRfMarker reports whether a Debian/Ubuntu version string carries a
// RapidFort rebuild marker — the same signal the feed annotator writes as the
// "rf" range identifier, so the routing decision here matches the DB build.
// Four substring forms cover every rebuild spelling in the live feed; shapes
// these forms do not match ("1surf1", "rfdebian") don't occur in real
// OS/ubuntu or OS/debian data.
//
//	"+rf"           Debian/Ubuntu revision suffix (e.g. "0:2.5.2-1build1+rf.1")
//	"rfubu"         Ubuntu rebuilds — matches "rfubu", "rfubuntu", "rfubujl"
//	".rf." / ".rf"  Debian bare-rf rebuild, mid-release or at the tail
func dpkgHasRfMarker(ver string) bool {
	return strings.Contains(ver, "+rf") || strings.Contains(ver, "rfubu") ||
		strings.Contains(ver, ".rf.") || strings.HasSuffix(ver, ".rf")
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
	case ftypes.RedHat, ftypes.Oracle, ftypes.Rocky, ftypes.Alma:
		s.comparer = version.NewRPMComparer()
		s.versionTrimmer = version.Major // "9.2" → "9"
	case ftypes.Amazon:
		s.comparer = version.NewRPMComparer()
		// OS.Name carries a parenthesized trailer that Major can't strip on
		// its own: "2023.12.20260831 (Amazon Linux)" → "2023", "2 (Karoo)" → "2".
		s.versionTrimmer = func(v string) string {
			fields := strings.Fields(v)
			if len(fields) == 0 {
				return ""
			}
			return version.Major(fields[0])
		}
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
	case ftypes.RedHat, ftypes.Oracle, ftypes.Rocky, ftypes.Alma, ftypes.Amazon:
		// The RPM families: the dist tag names the release, and for "fc" the
		// distribution too.
		switch tag, num := rpmDistTag(installedVer); tag {
		case "fc":
			return ecosystem.Fedora, num
		case "rf":
			return eco, ""
		case "el", "amzn":
			// Use the package's own dist-tag major, not osVer: an .elN or
			// .amznN package routes to the N-release bucket for its base
			// family even when the image itself is on a different major
			// (e.g. .el8 on a RHEL 9, Oracle 9, Rocky 9 or Alma 9 host).
			// Amazon is the exception: ".elN" there names the EL sources
			// the package was rebuilt from, not an Amazon release, so it
			// stays on the image's own release (e.g. ".el7" on AL2 is an
			// AL2 package, not an "amazon linux 7" one that never exists).
			// cmp.Or supplies osVer when the tag carries no major at all
			// ("7.76.1-26.el"), since that names no release of its own.
			if tag == "el" && s.baseOS == ftypes.Amazon {
				return eco, osVer
			}
			return eco, cmp.Or(num, osVer)
		default:
			// An untagged RPM names no distribution, so it is treated as a
			// build of the image's own release.
			return eco, osVer
		}
	default:
		// Families without a routing rule get the empty ecosystem, which has
		// no getter, so Detect skips their packages.
		return "", osVer
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
