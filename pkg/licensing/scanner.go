package licensing

import (
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
	"github.com/aquasecurity/trivy/pkg/set"
)

type ScannerOption struct {
	IgnoredLicenses   []string
	LicenseCategories map[types.LicenseCategory][]string
}

type Scanner struct {
	categories map[types.LicenseCategory][]string
}

func NewScanner(categories map[types.LicenseCategory][]string) Scanner {
	return Scanner{categories: categories}
}

func (s *Scanner) Scan(licenseName string) (types.LicenseCategory, string) {
	expr := NormalizeLicense(expression.SimpleExpr{License: licenseName})
	normalizedNames := set.New(expr.String()) // The license name with suffix (e.g. AGPL-1.0-or-later)
	if se, ok := expr.(expression.SimpleExpr); ok {
		normalizedNames.Append(se.License) // Also accept the license name without suffix (e.g. AGPL-1.0)
	}

	return s.LicenseCategory(normalizedNames)
}

// LicenseCategory returns license category and severity for licenseNames
func (s *Scanner) LicenseCategory(licenseNames set.Set[string]) (types.LicenseCategory, string) {
	for category, names := range s.categories {
		if licenseNames.Intersection(set.New(names...)).Size() > 0 {
			return category, categoryToSeverity(category).String()
		}
	}
	return types.CategoryUnknown, dbTypes.SeverityUnknown.String()
}
func categoryToSeverity(category types.LicenseCategory) dbTypes.Severity {
	switch category {
	case types.CategoryForbidden:
		return dbTypes.SeverityCritical
	case types.CategoryRestricted:
		return dbTypes.SeverityHigh
	case types.CategoryReciprocal:
		return dbTypes.SeverityMedium
	case types.CategoryNotice, types.CategoryPermissive, types.CategoryUnencumbered:
		return dbTypes.SeverityLow
	}
	return dbTypes.SeverityUnknown
}
