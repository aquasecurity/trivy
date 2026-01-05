package seal

import (
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

// SealSecurity matches packages patched by Seal Security.
// Seal Security provides patched versions of open source packages with their own
// vulnerability advisories. Their packages are identified by the special prefix or namespace
// in the package name (e.g., "seal-django", "@seal-security/ejs").
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
		// Java packages use groupId prefix: seal.sp
		// e.g. seal.sp1.org.eclipse.jetty:jetty-http, seal.sp2.org.eclipse.jetty:jetty-http
		return strings.HasPrefix(normalized, "seal.sp")
	case ecosystem.Npm:
		// Node packages use namespace: @seal-security/*
		// e.g. @seal-security/ejs, @seal-security/fastify-sealsec-multipart
		return strings.HasPrefix(normalized, "@seal-security/")
	case ecosystem.Go:
		// Go packages use domain prefix: sealsecurity.io/*
		// e.g. sealsecurity.io/github.com/Masterminds/goutils
		return strings.HasPrefix(normalized, "sealsecurity.io/")
	case ecosystem.Pip:
		// Python packages use name prefix: seal-*
		// e.g. seal-requests
		return strings.HasPrefix(normalized, "seal-")
	default:
		// Other ecosystems are not supported
		return false
	}
}
