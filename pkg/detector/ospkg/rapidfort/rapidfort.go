package rapidfort

import (
	"context"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	// rfvulnsrc is trivy-db's RapidFort vulnsrc — aliased because this
	// scanner package is also named "rapidfort". We import it so the scanner
	// can query the DB through the getter it exposes (see Scanner.vs).
	rfvulnsrc "github.com/aquasecurity/trivy-db/pkg/vulnsrc/rapidfort"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

// rpmIdentifierRe extracts the first el/fc distro identifier from an RPM version string.
// Examples: "7.76.1-26.el9_3.3" → "el9", "7.76.1-26.fc43" → "fc43".
var rpmIdentifierRe = regexp.MustCompile(`\b((?:el|fc)\d+)`)

// rfVersionSuffixRe matches RPM version strings that end with RapidFort's .rf or .rfN suffix
// (e.g. "7.76.1-26.rf1", "7.76.1-26.rf").  These are RHEL-based packages so the distro
// identifier must be derived from the OS version rather than the version string itself.
var rfVersionSuffixRe = regexp.MustCompile(`\.rf\d*$`)

// extractRPMIdentifier returns the first el/fc identifier embedded in an RPM version string.
// Returns "" when no identifier is present (ubuntu/alpine versions, bare .rf versions).
func extractRPMIdentifier(ver string) string {
	m := rpmIdentifierRe.FindStringSubmatch(ver)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

// Scanner detects vulnerabilities for RapidFort curated images by querying
// the RapidFort advisory data that was ingested by trivy-db.
type Scanner struct {
	baseOS   string
	comparer version.Comparer
	// versionTrimmer normalizes the installed OS version to the granularity
	// that RapidFort advisories are keyed on (e.g. "22.04.1" → "22.04" for Ubuntu,
	// "9.2" → "9" for RedHat).
	versionTrimmer func(string) string
	// vs is the RapidFort advisory getter exposed by trivy-db. The scanner
	// queries through this helper rather than db.Config.GetAdvisories so the
	// bucket-key format ("rapidfort <baseOS> <version>") lives entirely on
	// the trivy-db side. The scanner supplies (release, package) and never
	// composes the platform string itself.
	vs     rfvulnsrc.VulnSrcGetter
	logger *log.Logger
}

// NewScanner creates a RapidFort Scanner for the given base OS type.
func NewScanner(baseOS ftypes.OSType) *Scanner {
	var comparer version.Comparer
	var versionTrimmer func(string) string

	switch baseOS {
	case ftypes.Debian:
		comparer = version.NewDEBComparer()
		versionTrimmer = version.Major // "12.0.1" → "12"
	case ftypes.Ubuntu:
		comparer = version.NewDEBComparer()
		versionTrimmer = version.Minor // "22.04.1" → "22.04"
	case ftypes.Alpine:
		comparer = version.NewAPKComparer()
		versionTrimmer = version.Minor // "3.17.2" → "3.17"
	case ftypes.RedHat:
		comparer = version.NewRPMComparer()
		versionTrimmer = version.Major // "9.2" → "9"
	default:
		comparer = version.NewDEBComparer()
		versionTrimmer = version.Minor
	}

	baseOSLower := strings.ToLower(string(baseOS))
	return &Scanner{
		baseOS:         baseOSLower,
		comparer:       comparer,
		versionTrimmer: versionTrimmer,
		vs:             rfvulnsrc.NewVulnSrcGetter(baseOSLower),
		logger:         log.WithPrefix("rapidfort"),
	}
}

// Detect queries the RapidFort advisory DB for vulnerabilities in the given packages.
func (s *Scanner) Detect(ctx context.Context, osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	osVer = s.versionTrimmer(osVer)
	platformName := "rapidfort " + s.baseOS + " " + osVer
	log.InfoContext(ctx, "Detecting RapidFort advisories...",
		log.String("platform", platformName),
		log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		srcName := pkg.SrcName
		if srcName == "" {
			srcName = pkg.Name
		}

		installedVer := utils.FormatSrcVersion(pkg)

		// isRFPackage is true when the package name carries the RapidFort "rf-" prefix
		// (e.g. "rf-curl"). Used as a fallback in isRPMVulnerable: if no advisory range
		// matches the primary identifier, ranges tagged "rf" are also considered.
		// (The distro identifier itself is derived from installedVer inside
		// isRPMVulnerable, since that's the only place it is consumed.)
		isRFPackage := strings.HasPrefix(pkg.Name, "rf-")

		// Route DB queries through trivy-db's RapidFort getter (see the vs
		// field docstring). It builds the platform key from (baseOS, release)
		// on the trivy-db side, so this scanner just hands over the release
		// and package name and lets the getter compose the bucket lookup.
		advisories, err := s.vs.Get(db.GetParams{
			Release: osVer,
			PkgName: srcName,
		})
		if err != nil {
			return nil, xerrors.Errorf("failed to get RapidFort advisories for %s: %w", srcName, err)
		}

		// Fallback: some upstream RapidFort advisory files key entries by the binary
		// package name rather than the SRPM name.
		// Query the binary name as well and merge, deduping by VulnerabilityID with srcName entries winning.
		if pkg.Name != srcName {
			binAdvisories, err := s.vs.Get(db.GetParams{
				Release: osVer,
				PkgName: pkg.Name,
			})
			if err != nil {
				return nil, xerrors.Errorf("failed to get RapidFort advisories for %s: %w", pkg.Name, err)
			}
			if len(binAdvisories) > 0 {
				seen := make(map[string]struct{}, len(advisories))
				for _, adv := range advisories {
					seen[adv.VulnerabilityID] = struct{}{}
				}
				for _, adv := range binAdvisories {
					if _, ok := seen[adv.VulnerabilityID]; ok {
						continue
					}
					seen[adv.VulnerabilityID] = struct{}{}
					advisories = append(advisories, adv)
				}
			}
		}

		for _, adv := range advisories {
			if !s.isVulnerable(ctx, installedVer, isRFPackage, adv) {
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
		log.String("platform", platformName),
		log.Int("total_vulns", len(vulns)))

	return vulns, nil
}

func (s *Scanner) isVulnerable(ctx context.Context, installedVersion string, isRFPackage bool, adv dbTypes.Advisory) bool {
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

	// For RedHat/Fedora packages, use identifier-aware RPM vulnerability check to avoid
	// false positives from cross-distro RPM version ordering (e.g. el9 vs fc39 ranges).
	if s.baseOS == "redhat" {
		return s.isRPMVulnerable(ctx, installedVersion, isRFPackage, adv)
	}

	// Check if installed version lies in any vulnerable range.
	return s.checkConstraints(ctx, installedVersion, adv.VulnerableVersions)
}

// parseCustomIdentifiers extracts the ordered identifier list from Advisory.Custom.
// identifiers[i] corresponds to VulnerableVersions[i] in the advisory.
// Returns nil when the field is absent or malformed.
func parseCustomIdentifiers(custom any) []string {
	m, ok := custom.(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := m["identifiers"]
	if !ok {
		return nil
	}
	ids, ok := raw.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		if s, ok := id.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// isRPMVulnerable checks whether an RPM package is vulnerable by filtering advisory
// version ranges against the package's distro identifier (e.g. "el9", "fc43").
// Without this filtering, cross-distro ranges (el9 vs fc39) can produce false positives
// because RPM version ordering compares release strings without regard to the distro tag.
//
// Each range is matched using Advisory.Custom.identifiers[i], where identifiers[i]
// explicitly names the distro for VulnerableVersions[i]. Falls back to extracting the
// identifier via regex from the constraint string when no Custom identifier is present.
func (s *Scanner) isRPMVulnerable(ctx context.Context, installedVersion string, isRFPackage bool, adv dbTypes.Advisory) bool {
	// Derive the distro identifier from the installed version string. This logic
	// lives here (rather than being computed once in Detect and passed through)
	// because isRPMVulnerable is the only consumer — keeping the Detect loop free
	// of RedHat-specific setup means non-RPM scanners don't pay for a computation
	// they'd never use.
	//   - Standard el/fc packages: identifier embedded in version string
	//     (e.g. "7.76.1-26.el9_3.3" → "el9", "7.76.1-26.fc43" → "fc43").
	//   - RapidFort rf packages with a bare .rf/.rfN suffix carry no el/fc tag;
	//     tag them "rf" so they match advisory ranges built for RapidFort.
	//   - Otherwise default to the "el" family so we still match el9/el8/…
	//     advisory ranges rather than skipping them entirely.
	// (No baseOS guard on the .rf branch: isRPMVulnerable is only called when
	// baseOS == "redhat".)
	identifier := extractRPMIdentifier(installedVersion)
	if identifier == "" && rfVersionSuffixRe.MatchString(installedVersion) {
		identifier = "rf"
	}
	if identifier == "" {
		identifier = "el"
	}

	// Build a filtered slice of constraints that match the installed package's identifier.
	// Prefer Custom.identifiers[i] for explicit index-based matching; fall back to
	// regex extraction from the constraint string when no Custom identifier is available.
	// Prefix matching: "el" matches "el9", "el8", …; "el9" matches "el9" and "el9_3".
	// Constraints with no identifier are always included (universal ranges).
	customIdentifiers := parseCustomIdentifiers(adv.Custom)

	// isRFRange reports whether the range at index i is tagged for RapidFort builds.
	// With explicit Custom.identifiers: checks identifiers[i] == "rf".
	// Without: falls back to checking whether the constraint string itself contains
	// a .rf/.rfN version suffix.
	isRFRange := func(i int, constraintStr string) bool {
		if i < len(customIdentifiers) {
			return customIdentifiers[i] == "rf"
		}
		return rfVersionSuffixRe.MatchString(constraintStr)
	}

	var matchingRanges []string
	for i, constraintStr := range adv.VulnerableVersions {
		if i < len(customIdentifiers) {
			if !strings.HasPrefix(customIdentifiers[i], identifier) {
				continue // skip ranges belonging to a different distro identifier
			}
		} else {
			advIdentifier := extractRPMIdentifier(constraintStr)
			if advIdentifier != "" && !strings.HasPrefix(advIdentifier, identifier) {
				continue // skip ranges belonging to a different distro identifier
			}
		}
		matchingRanges = append(matchingRanges, constraintStr)
	}

	// Fallback for rf- prefixed packages: if no range matched the primary identifier
	// (e.g. package has an fc43 version but the advisory only has "rf" ranges), include
	// advisory ranges tagged for RapidFort builds. This handles cases where the installed
	// version doesn't carry a standard el/fc tag due to inconsistent build versioning.
	if isRFPackage && len(matchingRanges) == 0 {
		for i, constraintStr := range adv.VulnerableVersions {
			if isRFRange(i, constraintStr) {
				matchingRanges = append(matchingRanges, constraintStr)
			}
		}
	}

	return s.checkConstraints(ctx, installedVersion, matchingRanges)
}

func (s *Scanner) checkConstraints(ctx context.Context, installedVersion string, constraintsStr []string) bool {
	if installedVersion == "" {
		return false
	}

	for _, constraintStr := range constraintsStr {
		constraints, err := version.NewConstraints(constraintStr, s.comparer)
		if err != nil {
			s.logger.DebugContext(ctx, "Failed to parse version constraints",
				log.String("installed", installedVersion),
				log.String("constraint", constraintStr),
				log.Err(err))
			return false
		}

		satisfied, err := constraints.Check(installedVersion)
		if err != nil {
			s.logger.DebugContext(ctx, "Failed to check version constraints",
				log.String("installed", installedVersion),
				log.String("constraint", constraintStr),
				log.Err(err))
			return false
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

// IncludesThirdParty implements driver.ThirdPartyAware.
// RapidFort curated images may include patched versions of third-party packages
// (e.g. MariaDB, Docker), so we scan them too rather than filtering them out.
func (s *Scanner) IncludesThirdParty() bool {
	return true
}
