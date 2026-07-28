package rapidfort

import (
	"context"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
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

// extractDebIdentifier applies the RapidFort feed annotator's rule to a Debian/
// Ubuntu version string: "rf" wins over "ubuntu" when both substrings are
// present, and "" when neither is. Keeping the scanner rule identical to the
// annotator (see security-advisories repo) means an installed package and the
// advisory ranges it matches against use the same tag.
func extractDebIdentifier(ver string) string {
	if strings.Contains(ver, "rf") {
		return "rf"
	}
	if strings.Contains(ver, "ubuntu") {
		return "ubuntu"
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
	var (
		comparer       version.Comparer
		versionTrimmer func(string) string
		baseEcosystem  ecosystem.Type
	)

	switch baseOS {
	case ftypes.Debian:
		comparer = version.NewDEBComparer()
		versionTrimmer = version.Major // "12.0.1" → "12"
		baseEcosystem = ecosystem.Debian
	case ftypes.Ubuntu:
		comparer = version.NewDEBComparer()
		versionTrimmer = version.Minor // "22.04.1" → "22.04"
		baseEcosystem = ecosystem.Ubuntu
	case ftypes.Alpine:
		comparer = version.NewAPKComparer()
		versionTrimmer = version.Minor // "3.17.2" → "3.17"
		baseEcosystem = ecosystem.Alpine
	case ftypes.RedHat:
		comparer = version.NewRPMComparer()
		versionTrimmer = version.Major // "9.2" → "9"
		baseEcosystem = ecosystem.RedHat
	default:
		// Provider only creates scanners for Ubuntu/Alpine/RedHat; the DEB
		// comparer + minor trimmer here is a safe placeholder for any direct
		// caller. baseEcosystem stays empty and Get() will error at query time.
		comparer = version.NewDEBComparer()
		versionTrimmer = version.Minor
	}

	return &Scanner{
		baseOS:         strings.ToLower(string(baseOS)),
		comparer:       comparer,
		versionTrimmer: versionTrimmer,
		vs:             rfvulnsrc.NewVulnSrcGetter(baseEcosystem),
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

	// For Ubuntu packages, use identifier-aware check to distinguish RapidFort
	// rebuilds ("rf") from standard Ubuntu builds ("ubuntu") — the feed now
	// tags each event so a range for one flavor doesn't false-positive the other.
	if s.baseOS == "ubuntu" {
		return s.isDebVulnerable(ctx, installedVersion, adv)
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

// filterRangesByIdentifier keeps advisory ranges whose distro tag matches
// `identifier`. Shared between the RedHat and Ubuntu paths.
//
//   - extractRange derives a tag from a constraint string when
//     Custom.identifiers is absent. It may legitimately return "" for tags
//     the caller wants to treat as universal (e.g. RPM's rf ranges have no
//     el/fc tag and are kept unless the rf-package fallback fires).
//   - isRFRangeStr reports whether a constraint string is RF-tagged in the
//     absence of Custom.identifiers — used only by the rf-package fallback
//     loop. Callers that disable the fallback (isRFPackage=false) may pass nil.
//
// Ranges with no tag at all (both branches see ""/empty) are treated as
// universal and always kept, matching pre-annotation feed behaviour.
// Only the RedHat path uses the isRFPackage fallback; Ubuntu passes false
// because its annotator is expected to tag every event.
func filterRangesByIdentifier(
	adv dbTypes.Advisory,
	identifier string,
	isRFPackage bool,
	extractRange func(string) string,
	isRFRangeStr func(string) bool,
) []string {
	customIdentifiers := parseCustomIdentifiers(adv.Custom)

	isRFRange := func(i int, constraintStr string) bool {
		if i < len(customIdentifiers) {
			return customIdentifiers[i] == "rf"
		}
		return isRFRangeStr(constraintStr)
	}

	var matchingRanges []string
	for i, constraintStr := range adv.VulnerableVersions {
		if i < len(customIdentifiers) {
			if !strings.HasPrefix(customIdentifiers[i], identifier) {
				continue // skip ranges belonging to a different distro identifier
			}
		} else if advIdentifier := extractRange(constraintStr); advIdentifier != "" && !strings.HasPrefix(advIdentifier, identifier) {
			continue // skip ranges belonging to a different distro identifier
		}
		matchingRanges = append(matchingRanges, constraintStr)
	}

	// Fallback for rf- packages when no range matched the primary identifier: try
	// "rf"-tagged ranges. Handles rf- builds whose installed version doesn't
	// carry the primary tag (e.g. an rf- package on an fc43 host).
	if isRFPackage && len(matchingRanges) == 0 {
		for i, constraintStr := range adv.VulnerableVersions {
			if isRFRange(i, constraintStr) {
				matchingRanges = append(matchingRanges, constraintStr)
			}
		}
	}

	return matchingRanges
}

// isRPMVulnerable filters advisory ranges by the package's distro identifier
// ("el9", "fc43", …) before checking the version. Without this filter, RPM's
// identifier-blind release-string ordering yields cross-distro false positives
// (e.g. el9 vs fc39).
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

	// Note: extractRPMIdentifier only recognizes el/fc — rf ranges have no tag
	// and are kept as universal here, matching pre-annotation feed behaviour.
	// The rf-package fallback loop inside the helper handles rf ranges explicitly.
	matchingRanges := filterRangesByIdentifier(adv, identifier, isRFPackage,
		extractRPMIdentifier, rfVersionSuffixRe.MatchString)
	return s.checkConstraints(ctx, installedVersion, matchingRanges)
}

// isDebVulnerable filters advisory ranges by the package's Ubuntu identifier
// ("rf" for RapidFort rebuilds, "ubuntu" for standard Ubuntu) before checking
// the version. Follows the same rule the RapidFort feed annotator applies on
// the data side: "rf" wins over "ubuntu" as a version-string substring.
// Primary-only matching: the Ubuntu annotator is expected to tag every event
// (either "rf" or "ubuntu"), so a primary miss means the range genuinely does
// not apply — no rf-package fallback is performed here.
func (s *Scanner) isDebVulnerable(ctx context.Context, installedVersion string, adv dbTypes.Advisory) bool {
	// Identifier derivation (Ubuntu-only path — isDebVulnerable is its sole caller):
	//   - Versions containing "rf" (e.g. "0:3.12.10-1rfubu.1") → tag "rf",
	//     matching RapidFort-built advisory ranges.
	//   - Versions containing "ubuntu" (e.g. "0:2.39-0ubuntu8.3") → tag "ubuntu".
	//   - Otherwise default to "ubuntu" so untagged/legacy ranges still match.
	identifier := extractDebIdentifier(installedVersion)
	if identifier == "" {
		identifier = "ubuntu"
	}

	matchingRanges := filterRangesByIdentifier(adv, identifier, false, extractDebIdentifier, nil)
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

// FilterPackages implements driver.PackageFilter.
// RapidFort curated images may include patched versions of third-party packages
// (e.g. MariaDB, Docker), which RapidFort's own feed covers — so we keep every
// package here rather than letting the default third-party filter drop them.
func (s *Scanner) FilterPackages(_ context.Context, pkgs []ftypes.Package) []ftypes.Package {
	return pkgs
}
