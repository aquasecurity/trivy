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
	normalized := NormalizeLicenseNew(licenseName)

	switch normalized := normalized.(type) {
	case expression.SimpleExpr:
		return s.licenseToCategoryAndSeverity(normalized)
	case expression.CompoundExpr:
		return s.compoundLicenseToCategoryAndSeverity(normalized)
	}

	return types.CategoryUnknown, dbTypes.SeverityUnknown.String()
}

func (s *Scanner) licenseToCategoryAndSeverity(license expression.SimpleExpr) (types.LicenseCategory, string) {
	for category, names := range s.categories {
		if slices.Contains(names, license.License) {
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

func (s *Scanner) compoundLicenseToCategoryAndSeverity(license expression.CompoundExpr) (types.LicenseCategory, string) {
	switch license.Conjunction() {
	case expression.TokenAnd:
		return s.compoundLogicOperator(license, true)
	case expression.TokenOR:
		return s.compoundLogicOperator(license, false)
	default:
		return types.CategoryUnknown, dbTypes.SeverityUnknown.String()
	}
}

func (s *Scanner) compoundLogicOperator(license expression.CompoundExpr, findMax bool) (types.LicenseCategory, string) {
	lCategory, lSeverity := s.Scan(license.Left().String())
	rCategory, rSeverity := s.Scan(license.Right().String())

	if lSeverity == dbTypes.SeverityUnknown.String() || rSeverity == dbTypes.SeverityUnknown.String() {
		return types.CategoryUnknown, dbTypes.SeverityUnknown.String()
	}

	var logicOperator int
	if findMax {
		logicOperator = 1
	} else {
		logicOperator = -1
	}

	var compoundCategory types.LicenseCategory
	if 0 < logicOperator*dbTypes.CompareSeverityString(lSeverity, rSeverity) {
		compoundCategory = rCategory
	} else {
		compoundCategory = lCategory
	}

	return compoundCategory, categoryToSeverity(compoundCategory).String()
}
