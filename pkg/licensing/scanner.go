package licensing

import (
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
	expr := NormalizeLicense(expression.SimpleExpr{License: licenseName})
	normalizedNames := set.New(expr.String()) // The license name with suffix (e.g. AGPL-1.0-or-later)
	if se, ok := expr.(expression.SimpleExpr); ok {
		normalizedNames.Append(se.License) // Also accept the license name without suffix (e.g. AGPL-1.0)
	}

	for category, names := range s.categories {
		if normalizedNames.Intersection(set.New(names...)).Size() > 0 {
			return category, categoryToSeverity(category).String()
		}
	}
	return types.CategoryUnknown, dbTypes.SeverityUnknown.String()
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
