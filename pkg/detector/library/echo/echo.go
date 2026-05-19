package echo

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
)

func init() {
	library.RegisterSupplier(echoSupplier{
		pipComparer: pep440.NewComparer(pep440.AllowLocalSpecifier()),
	})
}

// echoSupplier matches pip packages patched by Echo.
// Echo provides patched versions of Python packages with their own vulnerability
// advisories. Their packages are identified by a PEP 440 local version suffix
// of the form "+echo.N" (e.g. "2.14.2+echo.1").
type echoSupplier struct {
	pipComparer compare.Comparer
}

func (echoSupplier) Name() string {
	return "echo"
}

// Match determines whether a package is provided by Echo.
// It expects a normalized package name (see vulnerability.NormalizePkgName).
// Echo packages are identified by a "+echo." segment in the version string.
// The "+echo." local segment cannot collide with real PyPI versions, so a
// suffix match is authoritative (Matched) rather than a Candidate.
func (echoSupplier) Match(eco ecosystem.Type, _, pkgVer string) library.MatchResult {
	if eco != ecosystem.Pip {
		return library.NoMatch
	}
	if strings.Contains(pkgVer, "+echo.") {
		return library.Matched
	}
	return library.NoMatch
}

// BucketPrefix returns the supplier-specific advisory bucket prefix.
func (e echoSupplier) BucketPrefix(eco ecosystem.Type) string {
	return fmt.Sprintf("%s %s::", e.Name(), eco)
}

// Comparer returns a version comparer for the given ecosystem.
// For pip (Python), it enables local version specifiers to correctly handle
// Echo version suffixes (e.g. "2.14.2+echo.1").
// For other ecosystems, it returns the default comparer unchanged.
func (e echoSupplier) Comparer(eco ecosystem.Type, defaultComparer compare.Comparer) compare.Comparer {
	if eco == ecosystem.Pip {
		return e.pipComparer
	}
	return defaultComparer
}
