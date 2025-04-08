package licensing

import (
	"slices"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
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
	normalized := NormalizeLicense(expression.SimpleExpr{License: licenseName})
	var normalizedName string
	switch normalized := normalized.(type) {
	case expression.SimpleExpr:
		normalizedName = normalized.License
	case expression.CompoundExpr:
		normalizedName = normalized.String()
	}

	for category, names := range s.categories {
		if slices.Contains(names, normalizedName) {
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
