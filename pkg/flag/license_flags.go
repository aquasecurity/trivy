package flag

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
)

var (
	LicenseFull = Flag{
		Name:       "license-full",
		ConfigName: "license.full",
		Value:      false,
		Usage:      "eagerly look for licenses in source code headers and license files",
	}
	IgnoredLicenses = Flag{
		Name:       "ignored-licenses",
		ConfigName: "license.ignored",
		Value:      []string{},
		Usage:      "specify a list of license to ignore",
	}
	LicenseConfidenceLevel = Flag{
		Name:       "license-confidence-level",
		ConfigName: "license.confidenceLevel",
		Value:      0.9,
		Usage:      "specify classifier confidence level",
	}

	// LicenseForbidden is an option only in a config file
	LicenseForbidden = Flag{
		ConfigName: "license.forbidden",
		Value:      licensing.ForbiddenLicenses,
		Usage:      "forbidden licenses",
	}
	// LicenseRestricted is an option only in a config file
	LicenseRestricted = Flag{
		ConfigName: "license.restricted",
		Value:      licensing.RestrictedLicenses,
		Usage:      "restricted licenses",
	}
	// LicenseReciprocal is an option only in a config file
	LicenseReciprocal = Flag{
		ConfigName: "license.reciprocal",
		Value:      licensing.ReciprocalLicenses,
		Usage:      "reciprocal licenses",
	}
	// LicenseNotice is an option only in a config file
	LicenseNotice = Flag{
		ConfigName: "license.notice",
		Value:      licensing.NoticeLicenses,
		Usage:      "notice licenses",
	}
	// LicensePermissive is an option only in a config file
	LicensePermissive = Flag{
		ConfigName: "license.permissive",
		Value:      licensing.PermissiveLicenses,
		Usage:      "permissive licenses",
	}
	// LicenseUnencumbered is an option only in a config file
	LicenseUnencumbered = Flag{
		ConfigName: "license.unencumbered",
		Value:      licensing.UnencumberedLicenses,
		Usage:      "unencumbered licenses",
	}
)

type LicenseFlagGroup struct {
	LicenseFull            *Flag
	IgnoredLicenses        *Flag
	LicenseConfidenceLevel *Flag

	// License Categories
	LicenseForbidden    *Flag // mapped to CRITICAL
	LicenseRestricted   *Flag // mapped to HIGH
	LicenseReciprocal   *Flag // mapped to MEDIUM
	LicenseNotice       *Flag // mapped to LOW
	LicensePermissive   *Flag // mapped to LOW
	LicenseUnencumbered *Flag // mapped to LOW
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
		LicenseFull:            &LicenseFull,
		IgnoredLicenses:        &IgnoredLicenses,
		LicenseConfidenceLevel: &LicenseConfidenceLevel,
		LicenseForbidden:       &LicenseForbidden,
		LicenseRestricted:      &LicenseRestricted,
		LicenseReciprocal:      &LicenseReciprocal,
		LicenseNotice:          &LicenseNotice,
		LicensePermissive:      &LicensePermissive,
		LicenseUnencumbered:    &LicenseUnencumbered,
	}
}

func (f *LicenseFlagGroup) Name() string {
	return "License"
}

func (f *LicenseFlagGroup) Flags() []*Flag {
	return []*Flag{f.LicenseFull, f.IgnoredLicenses, f.LicenseForbidden, f.LicenseRestricted, f.LicenseReciprocal,
		f.LicenseNotice, f.LicensePermissive, f.LicenseUnencumbered, f.LicenseConfidenceLevel}
}

func (f *LicenseFlagGroup) ToOptions() LicenseOptions {
	licenseCategories := map[types.LicenseCategory][]string{}
	licenseCategories[types.CategoryForbidden] = getStringSlice(f.LicenseForbidden)
	licenseCategories[types.CategoryRestricted] = getStringSlice(f.LicenseRestricted)
	licenseCategories[types.CategoryReciprocal] = getStringSlice(f.LicenseReciprocal)
	licenseCategories[types.CategoryNotice] = getStringSlice(f.LicenseNotice)
	licenseCategories[types.CategoryPermissive] = getStringSlice(f.LicensePermissive)
	licenseCategories[types.CategoryUnencumbered] = getStringSlice(f.LicenseUnencumbered)

	return LicenseOptions{
		LicenseFull:            getBool(f.LicenseFull),
		IgnoredLicenses:        getStringSlice(f.IgnoredLicenses),
		LicenseConfidenceLevel: getFloat(f.LicenseConfidenceLevel),
		LicenseCategories:      licenseCategories,
	}
}
