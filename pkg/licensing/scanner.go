package licensing

import (
	"slices"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
	"github.com/aquasecurity/trivy/pkg/log"
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
	visited := make(map[string]types.LicenseCategory)
	category := s.traverseLicenseExpression(licenseName, visited)

	return category, categoryToSeverity(category).String()
}

// traverseLicenseExpression recursive parses license expression to detect correct license category:
// For Simple Expression - use category of license
// For Compound Expression:
//   - `AND` operator - use category with maximum severity
//   - `OR` operator - use category with minimum severity
//   - one of expression has `UNKNOWN` category - use `UNKNOWN` category
func (s *Scanner) traverseLicenseExpression(licenseName string, visited map[string]types.LicenseCategory) types.LicenseCategory {
	category := types.CategoryUnknown

	detectCategoryAndSeverity := func(expr expression.Expression) expression.Expression {
		// Skip if we already checked this license
		if cat, ok := visited[licenseName]; ok {
			category = cat
			return expr
		}

		switch e := expr.(type) {
		case expression.SimpleExpr:
			category = s.licenseToCategory(e)
		case expression.CompoundExpr:
			category = s.compoundLicenseToCategory(e, visited)
		}

		visited[licenseName] = category
		return expr
	}

	_, err := expression.Normalize(licenseName, NormalizeLicense, detectCategoryAndSeverity)
	if err != nil {
		log.WithPrefix("license").Debug("Unable to detect license category", log.String("license", licenseName), log.Err(err))
		return types.CategoryUnknown
	}

	return category
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

func (s *Scanner) licenseToCategory(license expression.SimpleExpr) types.LicenseCategory {
	for category, names := range s.categories {
		if slices.Contains(names, license.License) {
			return category
		}
	}
	return types.CategoryUnknown
}

func (s *Scanner) compoundLicenseToCategory(license expression.CompoundExpr, visited map[string]types.LicenseCategory) types.LicenseCategory {
	switch license.Conjunction() {
	case expression.TokenAnd:
		return s.compoundLogicEvaluator(license, visited, true)
	case expression.TokenOR:
		return s.compoundLogicEvaluator(license, visited, false)
	default:
		return types.CategoryUnknown
	}
}

func (s *Scanner) compoundLogicEvaluator(license expression.CompoundExpr, visited map[string]types.LicenseCategory, findMax bool) types.LicenseCategory {
	lCategory := s.traverseLicenseExpression(license.Left().String(), visited)
	lSeverity := categoryToSeverity(lCategory)
	rCategory := s.traverseLicenseExpression(license.Right().String(), visited)
	rSeverity := categoryToSeverity(rCategory)

	if lSeverity == dbTypes.SeverityUnknown || rSeverity == dbTypes.SeverityUnknown {
		return types.CategoryUnknown
	}

	// Compare the two severities, returns a negative value if left is more severe than right
	comparison := dbTypes.CompareSeverityString(lSeverity.String(), rSeverity.String())
	leftIsMoreSevere := comparison < 0

	if (findMax && leftIsMoreSevere) || (!findMax && !leftIsMoreSevere) {
		return lCategory
	}
	return rCategory
}
