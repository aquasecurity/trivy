package licensing

import (
	"github.com/samber/lo"

	"path/filepath"
	"strings"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
	"github.com/aquasecurity/trivy/pkg/log"
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
	expr, err := expression.Normalize(licenseName, NormalizeLicense)
	if err != nil {
		return types.CategoryUnknown, ""
	}
	category := s.detectCategory(expr)

	return category, categoryToSeverity(category).String()
}

// detectCategory recursively parses license expression to detect correct license category:
// For the simple expression - use category of license
// For the compound expression:
//   - `AND` operator - use category with maximum severity
//   - `OR` operator - use category with minimum severity
//   - one of expression has `UNKNOWN` category - use `UNKNOWN` category
func (s *Scanner) detectCategory(license expression.Expression) types.LicenseCategory {
	var category types.LicenseCategory

	switch e := license.(type) {
	case expression.SimpleExpr:
		category = s.licenseToCategory(e)
	case expression.CompoundExpr:
		left := s.detectCategory(e.Left())
		right := s.detectCategory(e.Right())
		if left == types.CategoryUnknown || right == types.CategoryUnknown {
			category = types.CategoryUnknown
			break
		}
		comparison := func(a, b types.LicenseCategory) bool {
			if e.Conjunction() == expression.TokenAnd {
				return int(categoryToSeverity(a)) > int(categoryToSeverity(b)) // Take the maximum severity for `AND` operator
			}
			return int(categoryToSeverity(a)) < int(categoryToSeverity(b)) // Take the minimum severity for `OR` operator
		}
		category = lo.MaxBy([]types.LicenseCategory{left, right}, comparison)
	}

	return category
}

// ScanTextLicense checks license names from `categories` as glob patterns and matches licenseText against those patterns.
// If a match is found, it returns `unknown` category and severity.
func (s *Scanner) ScanTextLicense(licenseText string) (types.LicenseCategory, string) {
	// License text can contain `/` characters (e.g. links).
	// So we need to check each part of the license text separately.
	for _, part := range strings.Split(licenseText, "/") {
		if category, match := s.scanPartOfLicenseText(part); match {
			return category, categoryToSeverity(category).String()
		}
	}
	return types.CategoryUnknown, dbTypes.SeverityUnknown.String()
}

func (s *Scanner) scanPartOfLicenseText(license string) (types.LicenseCategory, bool) {
	for cat, names := range s.categories {
		for _, name := range names {
			match, err := filepath.Match(name, license)
			if err != nil {
				log.WithPrefix("license").Debug("failed to match license text", log.String("license text", license), log.Err(err))
				continue
			} else if match {
				return cat, true
			}
		}
	}
	return types.CategoryUnknown, false
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

func (s *Scanner) licenseToCategory(se expression.SimpleExpr) types.LicenseCategory {
	normalizedNames := set.New(se.String()) // The license name with suffix (e.g. AGPL-1.0-or-later)
	normalizedNames.Append(se.License)      // Also accept the license name without suffix (e.g. AGPL-1.0)

	for category, names := range s.categories {
		if normalizedNames.Intersection(set.New(names...)).Size() > 0 {
			return category
		}
	}

	return types.CategoryUnknown
}
