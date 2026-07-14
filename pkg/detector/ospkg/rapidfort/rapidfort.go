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
	"github.com/aquasecurity/trivy/pkg/set"
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
	// vs queries RapidFort advisories via trivy-db's getter. The getter owns
	// the bucket-key format ("rapidfort <baseOS> <version>"), so the scanner
	// just supplies (release, package) and never composes the platform string.
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

		isRFPackage := strings.HasPrefix(pkg.Name, "rf-")


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

// isRPMVulnerable filters advisory ranges by the package's distro identifier
// ("el9", "fc43", …) before checking the version. Without this filter, RPM's
// identifier-blind release-string ordering yields cross-distro false positives
// (e.g. el9 vs fc39). Ranges use Advisory.Custom.identifiers[i] when present,
// falling back to regex extraction from the constraint string.
func (s *Scanner) isRPMVulnerable(ctx context.Context, installedVersion string, isRFPackage bool, adv dbTypes.Advisory) bool {
	// Identifier derivation (RedHat-only path — isRPMVulnerable is its sole caller):
	//   - el/fc packages: identifier is embedded in the version string
	//     (e.g. "7.76.1-26.el9_3.3" → "el9", "7.76.1-26.fc43" → "fc43").
	//   - rf packages with a bare .rf/.rfN suffix carry no el/fc tag; tag them
	//     "rf" to match RapidFort-built advisory ranges.
	//   - Otherwise default to "el" so el9/el8/… ranges still match.
	identifier := extractRPMIdentifier(installedVersion)
	if identifier == "" && rfVersionSuffixRe.MatchString(installedVersion) {
		identifier = "rf"
	}
	if identifier == "" {
		identifier = "el"
	}

	// Filter constraints by identifier using Custom.identifiers[i] when present,
	// or regex extraction otherwise. Prefix matching: "el" covers "el9"/"el8"/…;
	// constraints with no identifier are treated as universal and always kept.
	customIdentifiers := parseCustomIdentifiers(adv.Custom)

	// isRFRange reports whether the range at index i is tagged for RapidFort builds
	// (Custom.identifiers[i] == "rf", or a .rf/.rfN suffix as fallback).
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

	// Fallback for rf- packages when no range matched the primary identifier: try
	// "rf"-tagged ranges. Handles rf- builds that don't carry a standard el/fc tag.
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
