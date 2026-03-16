package seal

import (
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
)

// SealSecurity matches packages patched by Seal Security.
// Seal Security provides patched versions of open source packages with their own
// vulnerability advisories. Their packages are identified by ecosystem-specific
// naming patterns:
//   - Maven:  seal.sp*.$groupId:$artifactId (e.g. seal.sp1, seal.sp2)
//   - npm:    @seal-security/$name
//   - Python: seal-$name
//   - Go:     sealsecurity.io/$name
//
// See also: pkg/detector/ospkg/seal/ for the OS package equivalent.
type SealSecurity struct{}

func (SealSecurity) Name() string {
	return "seal"
}

func (SealSecurity) Match(eco ecosystem.Type, pkgName, _ string) bool {
	normalized := vulnerability.NormalizePkgName(eco, pkgName)

	switch eco {
	case ecosystem.Maven:
		// e.g. seal.sp1.org.eclipse.jetty:jetty-http
		return strings.HasPrefix(normalized, "seal.sp")
	case ecosystem.Npm:
		// e.g. @seal-security/ejs, @seal-security/seal-ejs
		return strings.HasPrefix(normalized, "@seal-security/")
	case ecosystem.Pip:
		// e.g. seal-django
		return strings.HasPrefix(normalized, "seal-")
	case ecosystem.Go:
		// e.g. sealsecurity.io/github.com/Masterminds/goutils
		return strings.HasPrefix(normalized, "sealsecurity.io/")
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
