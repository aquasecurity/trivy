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

// dpkgHasRfMarker reports whether a Debian/Ubuntu version string carries a
// RapidFort rebuild marker. The feed uses two conventions: "+rf" (e.g.
// "0:2.5.2-1build1+rf.1") and "rfubu" (e.g. "0:2.46-10rfubu"). Both signal
// the same "rf" identifier on the DB side.
func dpkgHasRfMarker(ver string) bool {
	return strings.Contains(ver, "+rf") || strings.Contains(ver, "rfubu")
}

// getters is package-level because a getter is not tied to a scanner: the
// release is passed at Get time, so one getter serves both "rapidfort ubuntu
// 22.04" and the family-level "rapidfort ubuntu".
var getters = map[ecosystem.Type]rapidfort.VulnSrcGetter{
	ecosystem.Ubuntu: rapidfort.NewVulnSrcGetter(ecosystem.Ubuntu),
	ecosystem.Alpine: rapidfort.NewVulnSrcGetter(ecosystem.Alpine),
	ecosystem.RedHat: rapidfort.NewVulnSrcGetter(ecosystem.RedHat),
	ecosystem.Fedora: rapidfort.NewVulnSrcGetter(ecosystem.Fedora),
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
	case ftypes.Alpine:
		s.comparer = version.NewAPKComparer()
		s.versionTrimmer = version.Minor // "3.17.2" → "3.17"
	case ftypes.RedHat:
		s.comparer = version.NewRPMComparer()
		s.versionTrimmer = version.Major // "9.2" → "9"
	default:
		// Scanners are only created for Ubuntu/Alpine/RedHat; the DEB comparer
		// + minor trimmer here is a safe placeholder for any direct caller,
		// whose packages route to no ecosystem anyway.
		s.comparer = version.NewDEBComparer()
		s.versionTrimmer = version.Minor
	}

	return s
}

// route picks the (ecosystem, release) pair whose bucket the installed package
// belongs in. RapidFort's own rebuilds are not tied to a distribution release,
// so they drop it and land in the family-level bucket of their ecosystem.
func (s *Scanner) route(installedVer, osVer string) (ecosystem.Type, string) {
	switch s.baseOS {
	case ftypes.Ubuntu:
		if dpkgHasRfMarker(installedVer) {
			return ecosystem.Ubuntu, ""
		}
		return ecosystem.Ubuntu, osVer
	case ftypes.Alpine:
		return ecosystem.Alpine, osVer
	case ftypes.RedHat:
		switch tag, num := rpmDistTag(installedVer); tag {
		case "fc":
			return ecosystem.Fedora, num
		case "rf":
			return ecosystem.RedHat, ""
		case "el":
			// Use the package's own dist-tag major, not osVer: an .el8
			// package inside a RHEL 9 image belongs to the Red Hat 8 bucket.
			return ecosystem.RedHat, num
		default:
			// An untagged RPM names no distribution, so it is treated as a
			// build of the image's own release.
			return ecosystem.RedHat, osVer
		}
	}
	// Unsupported base OS: no getter matches the empty ecosystem.
	return "", osVer
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
