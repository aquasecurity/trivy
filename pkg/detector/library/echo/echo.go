package echo

import (
	"fmt"
	"regexp"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
)

// echoLocalSegmentRe matches the trailing Echo-specific version segment
// "+echo.N", e.g. "+echo.1" in "2.14.2+echo.1". This appears as a PEP 440
// local version (pip) and as a Maven build suffix (maven).
var echoLocalSegmentRe = regexp.MustCompile(`\+echo\.\d+$`)

func init() {
	library.RegisterSupplier(echoSupplier{
		pipComparer: pep440.NewComparer(pep440.AllowLocalSpecifier()),
	})
}

// echoSupplier matches language packages patched by Echo.
// Echo provides patched versions of Python (pip) and Java (maven) packages
// identified by a trailing "+echo.N" version segment.
type echoSupplier struct {
	pipComparer compare.Comparer
}

func (echoSupplier) Name() string {
	return "echo"
}

// Match determines whether a package is provided by Echo.
// Echo packages are identified by a trailing "+echo.N" segment in the version
// string, where N is a numeric revision (e.g. "2.14.2+echo.1").
func (echoSupplier) Match(eco ecosystem.Type, _, pkgVer string) library.MatchResult {
	switch eco {
	case ecosystem.Pip, ecosystem.Maven:
	default:
		return library.NoMatch
	}
	if echoLocalSegmentRe.MatchString(pkgVer) {
		return library.Matched
	}
	return library.NoMatch
}

// BucketPrefix returns the supplier-specific advisory bucket prefix.
func (e echoSupplier) BucketPrefix(eco ecosystem.Type) string {
	return fmt.Sprintf("%s %s::", e.Name(), eco)
}

// Comparer returns a version comparer for the given ecosystem.
// For pip (Python), it enables local version specifiers so PEP 440 ordering
// keeps the Echo suffix (e.g. "2.14.2+echo.1") instead of discarding it.
// Maven uses the default comparer, which already orders the "+echo.N" suffix.
func (e echoSupplier) Comparer(eco ecosystem.Type, defaultComparer compare.Comparer) compare.Comparer {
	if eco == ecosystem.Pip {
		return e.pipComparer
	}
	return defaultComparer
}
