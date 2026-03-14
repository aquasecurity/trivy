package seal

import (
	"regexp"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
)

// sealVersionSuffixRegex matches Seal Security version suffixes: +spX or -spX
// +spX for Maven and Python packages
// -spX for other packages
var sealVersionSuffixRegex = regexp.MustCompile(`[+-]sp\d+$`)

// SealSecurity matches packages patched by Seal Security.
// Seal Security provides patched versions of open source packages with their own
// vulnerability advisories. Their packages are identified by the special version suffix
// e.g. "+sp1", "-sp2".
// See also: pkg/detector/ospkg/seal/ for the OS package equivalent.
type SealSecurity struct{}

func (SealSecurity) Name() string {
	return "seal"
}

func (SealSecurity) Match(eco ecosystem.Type, pkgName, pkgVer string) bool {
	if hasSealVersionSuffix(pkgVer) {
		return true
	}

	normalized := vulnerability.NormalizePkgName(eco, pkgName)

	// In some cases, Seal renames package names by adding a special suffix.
	// e.g. "seal-django", "@seal-security/ejs".
	// However, for all cases except Maven, the version will have a suffix, so we should only check Maven packages.
	if eco == ecosystem.Maven {
		// e.g. seal.sp1.org.eclipse.jetty:jetty-http:1.0.0
		return strings.HasPrefix(normalized, "seal.sp")
	}

	return false
}

// Comparer returns a custom version comparer for the given ecosystem.
// For pip (Python), it enables local version specifiers (e.g. "4.2.8+seal.1").
// For other ecosystems, it returns nil to use the default comparer.
func (SealSecurity) Comparer(eco ecosystem.Type) compare.Comparer {
	if eco == ecosystem.Pip {
		return pep440.NewComparer(pep440.AllowLocalSpecifier())
	}
	return nil
}

// hasSealVersionSuffix checks if the version has a Seal Security suffix (+spX or -spX)
func hasSealVersionSuffix(version string) bool {
	return sealVersionSuffixRegex.MatchString(version)
}
