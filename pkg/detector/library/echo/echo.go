package echo

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
)

var (
	// echoLocalSegmentRe matches the "+echo.N" version segment used by the
	// existing Echo ecosystems.
	echoLocalSegmentRe = regexp.MustCompile(`\+echo\.\d+([._-]|$)`)

	// echoSemverSegmentRe requires the numeric Echo revision to be a complete
	// SemVer build identifier. Additional metadata identifiers remain valid,
	// but a "-" joined identifier (e.g. "+echo.1-extra") is rejected, unlike
	// echoLocalSegmentRe used by the other Echo ecosystems.
	echoSemverSegmentRe = regexp.MustCompile(`\+echo\.(0|[1-9]\d*)(\.|$)`)
)

func init() {
	library.RegisterSupplier(echoSupplier{
		pipComparer:   pep440.NewComparer(pep440.AllowLocalSpecifier()),
		npmComparer:   npm.NewComparer(npm.WithBuildMetadata()),
		nugetComparer: compare.NewGenericComparer(compare.WithBuildMetadata(version.BuildMetadataOrderNodeSemver)),
		goComparer:    compare.NewGenericComparer(compare.WithBuildMetadata(version.BuildMetadataOrderNodeSemver)),
	})
}

// echoSupplier matches language packages patched by Echo.
// Echo provides patched versions of Python (pip), Java (maven), JavaScript
// (npm), .NET (NuGet), and Go packages identified by a "+echo.N" version segment.
type echoSupplier struct {
	pipComparer   compare.Comparer
	npmComparer   compare.Comparer
	nugetComparer compare.Comparer
	goComparer    compare.Comparer
}

func (echoSupplier) Name() string {
	return "echo"
}

// Match determines whether a package is provided by Echo.
// Echo packages are identified by a "+echo.N" segment anywhere in the version
// string, where N is a numeric revision (e.g. "2.14.2+echo.1" or "2.14.2+echo.1.post1").
func (echoSupplier) Match(eco ecosystem.Type, _, pkgVer string) library.MatchResult {
	switch eco {
	case ecosystem.Go:
		if strings.Contains(pkgVer, "+echo.") &&
			echoSemverSegmentRe.MatchString(pkgVer) &&
			isValidGoSemVer(pkgVer) {
			return library.Matched
		}
		return library.NoMatch
	case ecosystem.Pip, ecosystem.Maven, ecosystem.Npm, ecosystem.NuGet:
	default:
		return library.NoMatch
	}
	if strings.Contains(pkgVer, "+echo.") && echoLocalSegmentRe.MatchString(pkgVer) {
		return library.Matched
	}
	return library.NoMatch
}

// isValidGoSemVer gates the lenient go-version comparer used below: without
// it, a malformed version that merely contains a "+echo." substring would
// still be routed to the Echo bucket instead of the upstream advisory.
func isValidGoSemVer(ver string) bool {
	return semver.IsValid(ver) || semver.IsValid("v"+ver)
}

// BucketPrefix returns the supplier-specific advisory bucket prefix.
func (e echoSupplier) BucketPrefix(eco ecosystem.Type) string {
	return fmt.Sprintf("%s %s::", e.Name(), eco)
}

// Comparer returns a version comparer for the given ecosystem.
// pip, npm, NuGet, and Go get comparers that keep the "+echo.N" suffix significant,
// PEP 440 local versions and SemVer build metadata are otherwise ignored;
// Maven's default comparer already orders it correctly.
func (e echoSupplier) Comparer(eco ecosystem.Type, defaultComparer compare.Comparer) compare.Comparer {
	switch eco {
	case ecosystem.Pip:
		return e.pipComparer
	case ecosystem.Npm:
		return e.npmComparer
	case ecosystem.NuGet:
		return e.nugetComparer
	case ecosystem.Go:
		return e.goComparer
	default:
		return defaultComparer
	}
}
