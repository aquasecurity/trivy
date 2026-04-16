package seal

import (
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
)

// SealSecurity matches packages patched by Seal Security.
// Seal Security provides patched versions of open source packages with their own
// vulnerability advisories. Their packages are identified by ecosystem-specific
// naming patterns:
//   - Maven:   seal.sp*.$groupId:$artifactId (e.g. seal.sp1, seal.sp2)
//   - npm:     @seal-security/$name
//   - Python:  seal-$name
//   - Go:      sealsecurity.io/$name
//   - Ruby:    seal-$name
//
// See also: pkg/detector/ospkg/seal/ for the OS package equivalent.
type SealSecurity struct{}

func (SealSecurity) Name() string {
	return "seal"
}

// Match determines whether a package is provided by Seal Security.
// It expects a normalized package name (see vulnerability.NormalizePkgName).
func (SealSecurity) Match(eco ecosystem.Type, pkgName, _ string) bool {
	switch eco {
	case ecosystem.Maven:
		// e.g. seal.sp1.org.eclipse.jetty:jetty-http
		return strings.HasPrefix(pkgName, "seal.sp")
	case ecosystem.Npm:
		// e.g. @seal-security/ejs
		return strings.HasPrefix(pkgName, "@seal-security/")
	case ecosystem.Pip, ecosystem.RubyGems:
		// e.g. seal-django (pip), seal-rack (rubygems)
		return strings.HasPrefix(pkgName, "seal-")
	case ecosystem.Go:
		// e.g. sealsecurity.io/github.com/Masterminds/goutils
		return strings.HasPrefix(pkgName, "sealsecurity.io/")
	}
	return false
}

// Comparer returns a custom version comparer for the given ecosystem.
// For pip (Python), it enables local version specifiers to correctly handle
// Seal Security version suffixes (e.g. "4.2.8+sp1").
// For other ecosystems, it returns nil to use the default comparer.
func (SealSecurity) Comparer(eco ecosystem.Type) compare.Comparer {
	if eco == ecosystem.Pip {
		return pep440.NewComparer(pep440.AllowLocalSpecifier())
	}
	return nil
}
