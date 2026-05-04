package library

import (
	"fmt"
	"slices"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

// Vendor represents a third-party security vendor that provides patched packages
// with their own vulnerability advisories. These vendors (e.g., Seal Security)
// offer patched versions of open source packages and maintain separate advisory
// databases that should be used instead of the standard ecosystem advisories.
//
// When a package is identified as coming from a vendor, Trivy queries the
// vendor-specific advisory bucket (e.g., "seal pip::") rather than the
// standard ecosystem bucket (e.g., "pip::").
type Vendor interface {
	// Name returns the vendor identifier used in the advisory bucket prefix.
	// For example, "seal" results in advisory queries to "seal pip::", "seal npm::", etc.
	Name() string

	// Match determines whether a package is provided by this vendor.
	// It receives the ecosystem type, a normalized package name
	// (see vulnerability.NormalizePkgName), and version to make the determination.
	Match(eco ecosystem.Type, pkgName, pkgVer string) bool

	// BucketPrefix returns the advisory bucket prefix for the given ecosystem.
	// For example, "seal pip::" for Seal Security pip packages.
	BucketPrefix(eco ecosystem.Type) string

	// Comparer returns a version comparer for the given ecosystem.
	// The defaultComparer is provided so the vendor can return it unchanged
	// when no custom comparison logic is needed.
	Comparer(eco ecosystem.Type, defaultComparer compare.Comparer) compare.Comparer
}

// vendors is the list of registered vendors. The first matching vendor wins.
// See also: pkg/detector/ospkg/seal/ for the OS package equivalent.
var vendors []Vendor

// RegisterVendor registers a new vendor for library vulnerability detection.
// It should be called from an init() function in the vendor's package.
func RegisterVendor(v Vendor) {
	vendors = append(vendors, v)
}

// DeregisterVendor removes a registered vendor by name.
// Use it to opt out of a vendor that was registered via
// pkg/detector/library/all (e.g., DeregisterVendor("seal")).
func DeregisterVendor(name string) {
	vendors = slices.DeleteFunc(vendors, func(v Vendor) bool {
		return v.Name() == name
	})
}

// lookupVendor finds the matching vendor for the given package.
// If a vendor matches, it is returned with ok=true.
// If no vendor matches, ok is false.
func lookupVendor(eco ecosystem.Type, pkgName, pkgVer string) (Vendor, bool) {
	for _, v := range vendors {
		if v.Match(eco, pkgName, pkgVer) {
			return v, true
		}
	}
	return nil, false
}

// defaultBucketPrefix returns the standard ecosystem bucket prefix (e.g. "pip::").
func defaultBucketPrefix(eco ecosystem.Type) string {
	return fmt.Sprintf("%s::", eco)
}
