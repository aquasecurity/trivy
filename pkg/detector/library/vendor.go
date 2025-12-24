package library

import (
	"fmt"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library/vendors/seal"
)

// Vendor represents a third-party security vendor that provides patched packages
// with their own vulnerability advisories. These vendors (e.g., Seal Security)
// offer patched versions of open source packages and maintain separate advisory
// databases that should be used instead of the standard ecosystem advisories.
//
// When a package is identified as coming from a vendor, Trivy queries the
// vendor-specific advisory bucket (e.g., "seal-pip::") rather than the
// standard ecosystem bucket (e.g., "pip::").
type Vendor interface {
	// Name returns the vendor identifier used in the advisory bucket prefix.
	// For example, "seal" results in advisory queries to "seal-pip::", "seal-npm::", etc.
	Name() string

	// Match determines whether a package is provided by this vendor.
	// It receives the ecosystem type, package name, and version to make the determination.
	// Vendors may use different identification methods such as package name prefixes,
	// suffixes, or version patterns.
	Match(eco ecosystem.Type, pkgName, pkgVer string) bool
}

// vendors is the list of registered vendors. The first matching vendor wins.
// See also: pkg/detector/ospkg/seal/ for the OS package equivalent.
var vendors = []Vendor{
	seal.SealSecurity{},
}

// resolveAdvisoryPrefix determines the advisory bucket prefix based on package info.
// For vendor packages, it returns a vendor-specific prefix (e.g., "seal-pip::").
// For regular packages, it returns the standard ecosystem prefix (e.g., "pip::").
func resolveAdvisoryPrefix(eco ecosystem.Type, pkgName, pkgVer string) string {
	for _, v := range vendors {
		if v.Match(eco, pkgName, pkgVer) {
			return fmt.Sprintf("%s-%s::", v.Name(), eco)
		}
	}
	return fmt.Sprintf("%s::", eco)
}
