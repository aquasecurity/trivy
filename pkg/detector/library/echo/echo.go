package echo

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
)

// echoLocalSegmentRe matches the trailing "+echo.N" version segment, e.g. "+echo.1" in "2.14.2+echo.1".
var echoLocalSegmentRe = regexp.MustCompile(`\+echo\.\d+$`)

func init() {
	library.RegisterSupplier(echoSupplier{
		pipComparer: pep440.NewComparer(pep440.AllowLocalSpecifier()),
		npmComparer: npm.NewComparer(npm.WithBuildMetadata()),
	})
}

// echoSupplier matches language packages patched by Echo.
// Echo provides patched versions of Python (pip), Java (maven), and JavaScript
// (npm) packages identified by a trailing "+echo.N" version segment.
type echoSupplier struct {
	pipComparer compare.Comparer
	npmComparer compare.Comparer
}

func (echoSupplier) Name() string {
	return "echo"
}

// Match determines whether a package is provided by Echo.
// Echo packages are identified by a trailing "+echo.N" segment in the version
// string, where N is a numeric revision (e.g. "2.14.2+echo.1").
func (echoSupplier) Match(eco ecosystem.Type, _, pkgVer string) library.MatchResult {
	switch eco {
	case ecosystem.Pip, ecosystem.Maven, ecosystem.Npm:
	default:
		return library.NoMatch
	}
	if strings.Contains(pkgVer, "+echo.") && echoLocalSegmentRe.MatchString(pkgVer) {
		return library.Matched
	}
	return library.NoMatch
}

// BucketPrefix returns the supplier-specific advisory bucket prefix.
func (e echoSupplier) BucketPrefix(eco ecosystem.Type) string {
	return fmt.Sprintf("%s %s::", e.Name(), eco)
}

// Comparer returns a version comparer for the given ecosystem.
// pip and npm get comparers that keep the "+echo.N" suffix significant, since
// PEP 440 local versions and SemVer build metadata are otherwise ignored;
// Maven's default comparer already orders it correctly.
func (e echoSupplier) Comparer(eco ecosystem.Type, defaultComparer compare.Comparer) compare.Comparer {
	switch eco {
	case ecosystem.Pip:
		return e.pipComparer
	case ecosystem.Npm:
		return e.npmComparer
	default:
		return defaultComparer
	}
}
