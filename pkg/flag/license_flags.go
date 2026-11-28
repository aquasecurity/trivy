package flag

import (
	"slices"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
)

var (
	LicenseFull = Flag[bool]{
		Name:          "license-full",
		ConfigName:    "license.full",
		Usage:         "eagerly look for licenses in source code headers and license files",
		TelemetrySafe: true,
	}
	IgnoredLicenses = Flag[[]string]{
		Name:       "ignored-licenses",
		ConfigName: "license.ignored",
		Usage:      "specify a list of licenses to ignore",
	}
	LicenseConfidenceLevel = Flag[float64]{
		Name:       "license-confidence-level",
		ConfigName: "license.confidenceLevel",
		Default:    0.9,
		Usage:      "specify license classifier's confidence level",
	}

	// LicenseForbidden is an option only in a config file
	LicenseForbidden = Flag[[]string]{
		ConfigName: "license.forbidden",
		Default:    expression.ForbiddenLicenses,
		Usage:      "forbidden licenses",
	}
	// LicenseRestricted is an option only in a config file
	LicenseRestricted = Flag[[]string]{
		ConfigName: "license.restricted",
		Default:    expression.RestrictedLicenses,
		Usage:      "restricted licenses",
	}
	// LicenseReciprocal is an option only in a config file
	LicenseReciprocal = Flag[[]string]{
		ConfigName: "license.reciprocal",
		Default:    expression.ReciprocalLicenses,
		Usage:      "reciprocal licenses",
	}
	// LicenseNotice is an option only in a config file
	LicenseNotice = Flag[[]string]{
		ConfigName: "license.notice",
		Default:    expression.NoticeLicenses,
		Usage:      "notice licenses",
	}
	// LicensePermissive is an option only in a config file
	LicensePermissive = Flag[[]string]{
		ConfigName: "license.permissive",
		Default:    expression.PermissiveLicenses,
		Usage:      "permissive licenses",
	}
	// LicenseUnencumbered is an option only in a config file
	LicenseUnencumbered = Flag[[]string]{
		ConfigName: "license.unencumbered",
		Default:    expression.UnencumberedLicenses,
		Usage:      "unencumbered licenses",
	}
)

type LicenseFlagGroup struct {
	LicenseFull            *Flag[bool]
	IgnoredLicenses        *Flag[[]string]
	LicenseConfidenceLevel *Flag[float64]

	// License Categories
	LicenseForbidden    *Flag[[]string] // mapped to CRITICAL
	LicenseRestricted   *Flag[[]string] // mapped to HIGH
	LicenseReciprocal   *Flag[[]string] // mapped to MEDIUM
	LicenseNotice       *Flag[[]string] // mapped to LOW
	LicensePermissive   *Flag[[]string] // mapped to LOW
	LicenseUnencumbered *Flag[[]string] // mapped to LOW
}

type LicenseOptions struct {
	LicenseFull            bool
	IgnoredLicenses        []string
	LicenseConfidenceLevel float64
	LicenseRiskThreshold   int
	LicenseCategories      map[types.LicenseCategory][]string
}

func NewLicenseFlagGroup() *LicenseFlagGroup {
	return &LicenseFlagGroup{
		LicenseFull:            LicenseFull.Clone(),
		IgnoredLicenses:        IgnoredLicenses.Clone(),
		LicenseConfidenceLevel: LicenseConfidenceLevel.Clone(),
		LicenseForbidden:       LicenseForbidden.Clone(),
		LicenseRestricted:      LicenseRestricted.Clone(),
		LicenseReciprocal:      LicenseReciprocal.Clone(),
		LicenseNotice:          LicenseNotice.Clone(),
		LicensePermissive:      LicensePermissive.Clone(),
		LicenseUnencumbered:    LicenseUnencumbered.Clone(),
	}
}

func (f *LicenseFlagGroup) Name() string {
	return "License"
}

func (f *LicenseFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.LicenseFull,
		f.IgnoredLicenses,
		f.LicenseForbidden,
		f.LicenseRestricted,
		f.LicenseReciprocal,
		f.LicenseNotice,
		f.LicensePermissive,
		f.LicenseUnencumbered,
		f.LicenseConfidenceLevel,
	}
}

// License IDs are case-insensitive, but the scanner interprets text patterns as regular expressions.
func licenseCategoryKey(name string) string {
	if strings.HasPrefix(name, licensing.LicenseTextPrefix) {
		return name
	}
	return strings.ToLower(name)
}

func (f *LicenseFlagGroup) ToOptions(opts *Options) error {
	// Keep categories ordered so conflicting explicit assignments produce a stable error.
	categories := []struct {
		category types.LicenseCategory
		flag     *Flag[[]string]
	}{
		{types.CategoryForbidden, f.LicenseForbidden},
		{types.CategoryRestricted, f.LicenseRestricted},
		{types.CategoryReciprocal, f.LicenseReciprocal},
		{types.CategoryNotice, f.LicenseNotice},
		{types.CategoryPermissive, f.LicensePermissive},
		{types.CategoryUnencumbered, f.LicenseUnencumbered},
	}

	licenseCategories := make(map[types.LicenseCategory][]string)
	explicitCategories := make(map[string]types.LicenseCategory)
	for _, c := range categories {
		licenseCategories[c.category] = slices.Clone(c.flag.Value())
		if !c.flag.IsSet() {
			continue
		}
		for _, license := range c.flag.Value() {
			name := licenseCategoryKey(license)
			if previous, ok := explicitCategories[name]; ok && previous != c.category {
				return xerrors.Errorf("license %q is explicitly configured in both %q and %q categories", license, previous, c.category)
			}
			explicitCategories[name] = c.category
		}
	}

	// Explicit lists replace their category's defaults and take precedence over
	// other categories' defaults, regardless of the license name's case.
	for _, c := range categories {
		if c.flag.IsSet() {
			continue
		}
		licenseCategories[c.category] = slices.DeleteFunc(licenseCategories[c.category], func(license string) bool {
			_, ok := explicitCategories[licenseCategoryKey(license)]
			return ok
		})
	}

	opts.LicenseOptions = LicenseOptions{
		LicenseFull:            f.LicenseFull.Value(),
		IgnoredLicenses:        f.IgnoredLicenses.Value(),
		LicenseConfidenceLevel: f.LicenseConfidenceLevel.Value(),
		LicenseCategories:      licenseCategories,
	}
	return nil
}
