package rapidfort

import (
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
var rpmDistTagRe = regexp.MustCompile(`\.(el|fc|rf)(\d*)`)

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

// dpkgHasRfMarker reports whether a Debian/Ubuntu version string carries the
// RapidFort rebuild marker. RapidFort's Ubuntu builds embed "rfubu" in the
// package revision (e.g. "0:2.46-10rfubu", "0:3.12.10-1rfubu.1") — matching
// the "rf" identifier the feed annotator writes on those events on the DB
// side, so the routing decision here uses the same signal.
func dpkgHasRfMarker(ver string) bool {
	return strings.Contains(ver, "rfubu")
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
	// getters holds one RapidFort advisory getter per ecosystem this scanner
	// dispatches to: RedHat has three (Red Hat, Fedora, RapidFort), Ubuntu and
	// Alpine one each.
	getters map[ecosystem.Type]rapidfort.VulnSrcGetter
	logger  *log.Logger
}

// NewScanner creates a RapidFort Scanner for the given base OS type.
func NewScanner(baseOS ftypes.OSType) *Scanner {
	s := &Scanner{
		baseOS:  baseOS,
		getters: make(map[ecosystem.Type]rapidfort.VulnSrcGetter),
		logger:  log.WithPrefix("rapidfort"),
	}

	switch baseOS {
	case ftypes.Ubuntu:
		s.comparer = version.NewDEBComparer()
		s.versionTrimmer = version.Minor // "22.04.1" → "22.04"
		// ubuntu and rf packages each resolve to their own bucket, mirroring
		// how the DB build splits the Ubuntu feed by range identifier.
		// RapidFortUbuntu (bucket "rapidfort ubuntu") holds dpkg-format rf
		// ranges only, so the dpkg comparator never sees an RPM-format
		// "rapidfort redhat" range.
		s.getters[ecosystem.Ubuntu] = rapidfort.NewVulnSrcGetter(ecosystem.Ubuntu)
		s.getters[ecosystem.RapidFortUbuntu] = rapidfort.NewVulnSrcGetter(ecosystem.RapidFortUbuntu)
	case ftypes.Alpine:
		s.comparer = version.NewAPKComparer()
		s.versionTrimmer = version.Minor // "3.17.2" → "3.17"
		s.getters[ecosystem.Alpine] = rapidfort.NewVulnSrcGetter(ecosystem.Alpine)
	case ftypes.RedHat:
		s.comparer = version.NewRPMComparer()
		s.versionTrimmer = version.Major // "9.2" → "9"
		// el/fc/rf packages each resolve to their own bucket.
		s.getters[ecosystem.RedHat] = rapidfort.NewVulnSrcGetter(ecosystem.RedHat)
		s.getters[ecosystem.Fedora] = rapidfort.NewVulnSrcGetter(ecosystem.Fedora)
		s.getters[ecosystem.RapidFort] = rapidfort.NewVulnSrcGetter(ecosystem.RapidFort)
	default:
		// Provider only creates scanners for Ubuntu/Alpine/RedHat; the DEB
		// comparer + minor trimmer here is a safe placeholder for any direct
		// caller. getters stays empty, so Detect finds no advisories.
		s.comparer = version.NewDEBComparer()
		s.versionTrimmer = version.Minor
	}

	return s
}

// route maps an installed package to its RapidFort bucket's ecosystem and release.
func (s *Scanner) route(installedVer, osVer string) (ecosystem.Type, string) {
	switch s.baseOS {
	case ftypes.Ubuntu:
		if dpkgHasRfMarker(installedVer) {
			return ecosystem.RapidFortUbuntu, "" // "rfubu"-marked → dpkg-only "rapidfort ubuntu" bucket
		}
		return ecosystem.Ubuntu, osVer
	case ftypes.Alpine:
		return ecosystem.Alpine, osVer
	case ftypes.RedHat:
		switch tag, num := rpmDistTag(installedVer); tag {
		case "fc":
			return ecosystem.Fedora, num // "fc43" → "rapidfort fedora 43" bucket
		case "rf":
			return ecosystem.RapidFort, "" // ".rf"/".rfN" → distribution-less "rapidfort" bucket
		default: // "el" or untagged → "rapidfort Red Hat <major>" bucket, keyed by the OS version
			return ecosystem.RedHat, osVer
		}
	}
	return "", osVer // unsupported base OS; getters is empty and the lookup misses
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
		srcName := pkg.SrcName
		if srcName == "" {
			srcName = pkg.Name
		}

		installedVer := utils.FormatSrcVersion(pkg)

		// Route the package to the bucket that holds its advisories (a RedHat
		// image mixes RedHat/Fedora/RapidFort packages across three buckets).
		eco, release := s.route(installedVer, osVer)
		vs, ok := s.getters[eco]
		if !ok {
			continue // ecosystem not served by this scanner
		}

		advisories, err := vs.Get(db.GetParams{
			Release: release,
			PkgName: srcName,
		})
		if err != nil {
			return nil, xerrors.Errorf("failed to get RapidFort advisories for %s: %w", srcName, err)
		}

		// Fallback: some upstream RapidFort advisory files key entries by the binary
		// package name rather than the SRPM name.
		// Query the binary name as well and merge, deduping by VulnerabilityID with srcName entries winning.
		if pkg.Name != srcName {
			binAdvisories, err := vs.Get(db.GetParams{
				Release: release,
				PkgName: pkg.Name,
			})
			if err != nil {
				return nil, xerrors.Errorf("failed to get RapidFort advisories for %s: %w", pkg.Name, err)
			}
			if len(binAdvisories) > 0 {
				// Seed the set with CVE IDs already returned for the SRPM query so
				// srcName entries win when the same CVE appears in both feeds.
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

// isVulnerable reports whether installedVersion is affected by adv.
func (s *Scanner) isVulnerable(ctx context.Context, installedVersion string, adv dbTypes.Advisory) bool {
	if installedVersion == "" {
		return false
	}

	// Check fixed versions first: if installed equals any patched version, not vulnerable.
	for _, fixedVer := range adv.PatchedVersions {
		if result, err := s.comparer.Compare(installedVersion, fixedVer); err == nil && result == 0 {
			return false
		}
	}

	// No vulnerable ranges means all versions are considered vulnerable.
	if len(adv.VulnerableVersions) == 0 {
		return true
	}

	// Check if installed version lies in any vulnerable range.
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

// IsSupportedVersion always returns true.
// RapidFort provides its own curated advisories including for EOL distributions,
// so we never reject a scan based on OS version alone.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}

var _ driver.PackageFilter = (*Scanner)(nil)

// FilterPackages implements driver.PackageFilter.
// RapidFort curated images may include patched versions of third-party packages
// (e.g. MariaDB, Docker), which RapidFort's own feed covers — so we keep every
// package here rather than letting the default third-party filter drop them.
func (s *Scanner) FilterPackages(_ context.Context, pkgs []ftypes.Package) []ftypes.Package {
	return pkgs
}
