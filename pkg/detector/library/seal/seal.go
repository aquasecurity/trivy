package seal

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
)

// Seal Security appends an ecosystem-specific patch-level suffix to the upstream
// version of a no-prefix package. Each ecosystem uses its own separator, so the
// suffix is matched per ecosystem rather than with a single shared pattern.
//
// Both public ("spN") and private ("spNpM") sealed versions are matched: a
// private version carries an extra "pM" iteration on top of the sealed version
// (e.g. "2.7.4-sp2p1"). See
// https://docs.sealsecurity.io/reference/naming-and-versioning/sp-model and
// https://docs.sealsecurity.io/reference/naming-and-versioning/per-ecosystem
var (
	// Maven and PyPI: "$version+spN[pM]" (e.g. "9.4.48+sp1", "4.2.8+sp1p1").
	plusSealSuffix = regexp.MustCompile(`\+sp\d+(?:p\d+)?$`)
	// npm: "$version-spN[pM]" (e.g. "3.1.8-sp1", "3.1.8-sp1p1").
	npmSealSuffix = regexp.MustCompile(`-sp\d+(?:p\d+)?$`)
	// Go: "$version-spN[pM]", optionally followed by the "+incompatible" build
	// metadata Go adds to major-version-2+ modules without a /vN path
	// (e.g. "v1.1.1-sp1", "v2.0.0-sp1p1+incompatible").
	goSealSuffix = regexp.MustCompile(`-sp\d+(?:p\d+)?(?:\+incompatible)?$`)
	// RubyGems: "$version.0.1.spN[pM]" (e.g. "2.0.7.0.1.sp1", "2.0.7.0.1.sp1p1").
	rubySealSuffix = regexp.MustCompile(`\.0\.1\.sp\d+(?:p\d+)?$`)
)

func init() {
	library.RegisterVendor(sealSecurity{
		pipComparer: pep440.NewComparer(pep440.AllowLocalSpecifier()),
	})
}

// sealSecurity matches packages patched by Seal Security.
// Seal Security provides patched versions of open source packages with their own
// vulnerability advisories. Seal ships packages under two naming schemes:
//
// Renamed packages carry an ecosystem-specific name prefix:
//   - Maven:   seal.sp*.$groupId:$artifactId (e.g. seal.sp1, seal.sp2)
//   - npm:     @seal-security/$name
//   - Python:  seal-$name
//   - Go:      sealsecurity.io/$name
//   - Ruby:    seal-$name
//
// No-prefix packages keep the upstream name and only add a version suffix
// (e.g. "+sp1"/"-sp1"/".sp1"). They are detected by that suffix:
//   - Maven/PyPI: the "+spN" suffix cannot collide with real versions, so a
//     suffix match is authoritative (Matched).
//   - Go/npm/Ruby: the "-spN"/".spN" suffix can also appear on real packages,
//     so a suffix match is only a Candidate, confirmed against the Seal
//     advisory bucket (see library.Driver.advisories).
//
// See also: pkg/detector/ospkg/seal/ for the OS package equivalent.
type sealSecurity struct {
	pipComparer compare.Comparer
}

func (sealSecurity) Name() string {
	return "seal"
}

// Match determines whether a package is provided by Seal Security.
// It expects a normalized package name (see vulnerability.NormalizePkgName).
func (sealSecurity) Match(eco ecosystem.Type, pkgName, pkgVer string) library.MatchResult {
	// A Seal package is marked either in the name (renamed packages) or in the
	// version by the "spN" patch-level suffix (no-prefix packages). If neither
	// marker is present, it cannot be a Seal package, so skip the per-ecosystem
	// regexes. See
	//   - https://docs.sealsecurity.io/reference/naming-and-versioning/renamed-packages
	//   - https://docs.sealsecurity.io/reference/naming-and-versioning/per-ecosystem
	if !strings.Contains(pkgName, "seal") && !strings.Contains(pkgVer, "sp") {
		return library.NoMatch
	}

	switch eco {
	case ecosystem.Maven:
		// Renamed: e.g. seal.sp1.org.eclipse.jetty:jetty-http
		if rest, ok := strings.CutPrefix(pkgName, "seal.sp"); ok && rest != "" && unicode.IsDigit(rune(rest[0])) {
			return library.Matched
		}
		// No-prefix: the "+spN" version suffix cannot collide with real Maven versions.
		if plusSealSuffix.MatchString(pkgVer) {
			return library.Matched
		}
	case ecosystem.Pip:
		// Renamed: e.g. seal-django
		if strings.HasPrefix(pkgName, "seal-") {
			return library.Matched
		}
		// No-prefix: the "+spN" version suffix cannot collide with real PyPI versions.
		if plusSealSuffix.MatchString(pkgVer) {
			return library.Matched
		}
	case ecosystem.Npm:
		// Renamed: e.g. @seal-security/ejs
		if strings.HasPrefix(pkgName, "@seal-security/") {
			return library.Matched
		}
		// No-prefix: the "-spN" version suffix can also appear on real npm
		// packages, so confirm it against the Seal advisory bucket.
		if npmSealSuffix.MatchString(pkgVer) {
			return library.Candidate
		}
	case ecosystem.Go:
		// Renamed: e.g. sealsecurity.io/github.com/Masterminds/goutils
		if strings.HasPrefix(pkgName, "sealsecurity.io/") {
			return library.Matched
		}
		// No-prefix: the "-spN" version suffix can also appear on real Go
		// modules, so confirm it against the Seal advisory bucket.
		if goSealSuffix.MatchString(pkgVer) {
			return library.Candidate
		}
	case ecosystem.RubyGems:
		// Renamed: e.g. seal-rack
		if strings.HasPrefix(pkgName, "seal-") {
			return library.Matched
		}
		// No-prefix: the ".0.1.spN" version suffix (e.g. 2.0.7.0.1.sp1) can
		// also appear on real gems as prerelease segments, so confirm it
		// against the Seal advisory bucket.
		if rubySealSuffix.MatchString(pkgVer) {
			return library.Candidate
		}
	}
	return library.NoMatch
}

// BucketPrefix returns the vendor-specific advisory bucket prefix.
func (s sealSecurity) BucketPrefix(eco ecosystem.Type) string {
	return fmt.Sprintf("%s %s::", s.Name(), eco)
}

// Comparer returns a version comparer for the given ecosystem.
// For pip (Python), it enables local version specifiers to correctly handle
// Seal Security version suffixes (e.g. "4.2.8+sp1").
// For other ecosystems, it returns the default comparer unchanged.
func (s sealSecurity) Comparer(eco ecosystem.Type, defaultComparer compare.Comparer) compare.Comparer {
	if eco == ecosystem.Pip {
		return s.pipComparer
	}
	return defaultComparer
}
