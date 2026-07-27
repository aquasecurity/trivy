package library

import (
	"fmt"
	"slices"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

// MatchResult describes how strongly a package matches a supplier.
type MatchResult int

const (
	// NoMatch indicates the package does not belong to the supplier.
	NoMatch MatchResult = iota

	// Matched indicates the package definitely belongs to the supplier.
	Matched

	// Candidate indicates the package might belong to the supplier, e.g. a version
	// suffix that can also appear on real packages (`-spN` on Go/npm packages).
	// Callers should confirm a Candidate before relying on it, and otherwise fall
	// back to default (non-supplier) handling.
	Candidate
)

// Supplier represents a third-party security supplier that provides patched packages
// with their own vulnerability advisories. These suppliers (e.g., Seal Security)
// offer patched versions of open source packages and maintain separate advisory
// databases that should be used instead of the standard ecosystem advisories.
//
// When a package is identified as coming from a supplier, Trivy queries the
// supplier-specific advisory bucket (e.g., "seal pip::") rather than the
// standard ecosystem bucket (e.g., "pip::").
type Supplier interface {
	// Name returns the supplier identifier used in the advisory bucket prefix.
	// For example, "seal" results in advisory queries to "seal pip::", "seal npm::", etc.
	Name() string

	// Match determines whether a package is provided by this supplier.
	// It receives the ecosystem type, a normalized package name
	// (see vulnerability.NormalizePkgName), and version to make the determination.
	Match(eco ecosystem.Type, pkgName, pkgVer string) MatchResult

	// BucketPrefix returns the advisory bucket prefix for the given ecosystem.
	// For example, "seal pip::" for Seal Security pip packages.
	BucketPrefix(eco ecosystem.Type) string

	// Comparer returns a version comparer for the given ecosystem.
	// The defaultComparer is provided so the supplier can return it unchanged
	// when no custom comparison logic is needed.
	Comparer(eco ecosystem.Type, defaultComparer compare.Comparer) compare.Comparer
}

// suppliers is the list of registered suppliers. The first matching supplier wins.
// See also: pkg/detector/ospkg/seal/ for the OS package equivalent.
var suppliers []Supplier

// RegisterSupplier registers a new supplier for library vulnerability detection.
// It should be called from an init() function in the supplier's package.
func RegisterSupplier(v Supplier) {
	suppliers = append(suppliers, v)
}

// DeregisterSupplier removes a registered supplier by name.
// Use it to opt out of a supplier that was registered via
// pkg/detector/library/all (e.g., DeregisterSupplier("seal")).
func DeregisterSupplier(name string) {
	suppliers = slices.DeleteFunc(suppliers, func(v Supplier) bool {
		return v.Name() == name
	})
}

// lookupSupplier finds the matching supplier for the given package.
// If a supplier matches, it is returned together with its match result
// (Matched or Candidate). If no supplier matches, it returns nil and NoMatch.
func lookupSupplier(eco ecosystem.Type, pkgName, pkgVer string) (Supplier, MatchResult) {
	for _, v := range suppliers {
		if res := v.Match(eco, pkgName, pkgVer); res != NoMatch {
			return v, res
		}
	}
	return nil, NoMatch
}

// defaultBucketPrefix returns the standard ecosystem bucket prefix (e.g. "pip::").
func defaultBucketPrefix(eco ecosystem.Type) string {
	return fmt.Sprintf("%s::", eco)
}
