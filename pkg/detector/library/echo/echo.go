package echo

import (
	"regexp"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
)

// echoLocalSegmentRe matches the Echo-specific version segment "+echo.N",
// e.g. "+echo.1" in "2.14.2+echo.1". This appears both as a PEP 440 local
// version (pip) and as a Maven build suffix (maven).
var echoLocalSegmentRe = regexp.MustCompile(`\+echo\.\d+`)

func init() {
	library.RegisterVendor(echoVendor{
		pipComparer: pep440.NewComparer(pep440.AllowLocalSpecifier()),
	})
}

// echoVendor matches language packages patched by Echo.
// Echo provides patched versions of Python (pip) and Java (maven) packages with
// their own vulnerability advisories. Their packages are identified by a version
// suffix of the form "+echo.N" (e.g. "2.14.2+echo.1").
type echoVendor struct {
	pipComparer compare.Comparer
}

func (echoVendor) Name() string {
	return "echo"
}

// Match determines whether a package is provided by Echo.
// It expects a normalized package name (see vulnerability.NormalizePkgName).
// Echo packages are identified by a "+echo.N" segment in the version string,
// where N is a numeric revision (e.g. "2.14.2+echo.1"). Echo patches both
// Python (pip) and Java (maven) packages using this same suffix convention.
func (echoVendor) Match(eco ecosystem.Type, _, pkgVer string) bool {
	switch eco {
	case ecosystem.Pip, ecosystem.Maven:
		return strings.Contains(pkgVer, "+echo.") && echoLocalSegmentRe.MatchString(pkgVer)
	default:
		return false
	}
}

// BucketPrefix returns the vendor-specific advisory bucket prefix.
func (e echoVendor) BucketPrefix(eco ecosystem.Type) string {
	return e.Name() + " " + string(eco) + "::"
}

// Comparer returns a version comparer for the given ecosystem.
// For pip (Python), it enables local version specifiers so PEP 440 ordering
// keeps the Echo suffix (e.g. "2.14.2+echo.1") instead of discarding it.
// For maven (and other ecosystems) the default comparer already orders the
// "+echo.N" suffix correctly, so it is returned unchanged.
func (e echoVendor) Comparer(eco ecosystem.Type, defaultComparer compare.Comparer) compare.Comparer {
	if eco == ecosystem.Pip {
		return e.pipComparer
	}
	return defaultComparer
}
