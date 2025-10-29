package flag

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
	"github.com/aquasecurity/trivy/pkg/set"
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
		Usage:      "specify a list of license to ignore",
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
		Default:    expression.ForbiddenLicenses.Items(),
		Usage:      "forbidden licenses",
	}
	// LicenseRestricted is an option only in a config file
	LicenseRestricted = Flag[[]string]{
		ConfigName: "license.restricted",
		Default:    expression.RestrictedLicenses.Items(),
		Usage:      "restricted licenses",
	}
	// LicenseReciprocal is an option only in a config file
	LicenseReciprocal = Flag[[]string]{
		ConfigName: "license.reciprocal",
		Default:    expression.ReciprocalLicenses.Items(),
		Usage:      "reciprocal licenses",
	}
	// LicenseNotice is an option only in a config file
	LicenseNotice = Flag[[]string]{
		ConfigName: "license.notice",
		Default:    expression.NoticeLicenses.Items(),
		Usage:      "notice licenses",
	}
	// LicensePermissive is an option only in a config file
	LicensePermissive = Flag[[]string]{
		ConfigName: "license.permissive",
		Default:    expression.PermissiveLicenses.Items(),
		Usage:      "permissive licenses",
	}
	// LicenseUnencumbered is an option only in a config file
	LicenseUnencumbered = Flag[[]string]{
		ConfigName: "license.unencumbered",
		Default:    expression.UnencumberedLicenses.Items(),
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
	LicenseCategories      map[types.LicenseCategory]set.Set[string]
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

func (f *LicenseFlagGroup) ToOptions(opts *Options) error {
	licenseCategories := make(map[types.LicenseCategory]set.Set[string])
	licenseCategories[types.CategoryForbidden] = set.NewCaseInsensitive(f.LicenseForbidden.Value()...)
	licenseCategories[types.CategoryRestricted] = set.NewCaseInsensitive(f.LicenseRestricted.Value()...)
	licenseCategories[types.CategoryReciprocal] = set.NewCaseInsensitive(f.LicenseReciprocal.Value()...)
	licenseCategories[types.CategoryNotice] = set.NewCaseInsensitive(f.LicenseNotice.Value()...)
	licenseCategories[types.CategoryPermissive] = set.NewCaseInsensitive(f.LicensePermissive.Value()...)
	licenseCategories[types.CategoryUnencumbered] = set.NewCaseInsensitive(f.LicenseUnencumbered.Value()...)

	opts.LicenseOptions = LicenseOptions{
		LicenseFull:            f.LicenseFull.Value(),
		IgnoredLicenses:        f.IgnoredLicenses.Value(),
		LicenseConfidenceLevel: f.LicenseConfidenceLevel.Value(),
		LicenseCategories:      licenseCategories,
	}
	return nil
}
