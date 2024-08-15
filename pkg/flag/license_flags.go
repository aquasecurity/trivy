package flag

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
)

var (
	LicenseFull = Flag[bool]{
		Name:       "license-full",
		ConfigName: "license.full",
		Usage:      "eagerly look for licenses in source code headers and license files",
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
	LicenseTextCacheDir = Flag[string]{
		Name:       "license-text-cacheDir",
		ConfigName: "license.cacheDir",
		Default:    "",
		Usage:      "specify the cache dir to persist license texts found in license scanning",
	}
	LicenseScanWorkers = Flag[int]{
		Name:       "license-scan-workers",
		ConfigName: "license.scanWorkers",
		Default:    5,
		Usage:      "specify the number of parallel workers needed for license scanning",
	}

	// LicenseForbidden is an option only in a config file
	LicenseForbidden = Flag[[]string]{
		ConfigName: "license.forbidden",
		Default:    licensing.ForbiddenLicenses,
		Usage:      "forbidden licenses",
	}
	// LicenseRestricted is an option only in a config file
	LicenseRestricted = Flag[[]string]{
		ConfigName: "license.restricted",
		Default:    licensing.RestrictedLicenses,
		Usage:      "restricted licenses",
	}
	// LicenseReciprocal is an option only in a config file
	LicenseReciprocal = Flag[[]string]{
		ConfigName: "license.reciprocal",
		Default:    licensing.ReciprocalLicenses,
		Usage:      "reciprocal licenses",
	}
	// LicenseNotice is an option only in a config file
	LicenseNotice = Flag[[]string]{
		ConfigName: "license.notice",
		Default:    licensing.NoticeLicenses,
		Usage:      "notice licenses",
	}
	// LicensePermissive is an option only in a config file
	LicensePermissive = Flag[[]string]{
		ConfigName: "license.permissive",
		Default:    licensing.PermissiveLicenses,
		Usage:      "permissive licenses",
	}
	// LicenseUnencumbered is an option only in a config file
	LicenseUnencumbered = Flag[[]string]{
		ConfigName: "license.unencumbered",
		Default:    licensing.UnencumberedLicenses,
		Usage:      "unencumbered licenses",
	}
)

type LicenseFlagGroup struct {
	LicenseFull            *Flag[bool]
	IgnoredLicenses        *Flag[[]string]
	LicenseConfidenceLevel *Flag[float64]
	LicenseTextCacheDir    *Flag[string]
	LicenseScanWorkers     *Flag[int]

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
	LicenseTextCacheDir    string
	LicenseScanWorkers     int
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
		LicenseTextCacheDir:    LicenseTextCacheDir.Clone(),
		LicenseScanWorkers:     LicenseScanWorkers.Clone(),
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
		f.LicenseTextCacheDir,
		f.LicenseScanWorkers,
	}
}

func (f *LicenseFlagGroup) ToOptions() (LicenseOptions, error) {
	if err := parseFlags(f); err != nil {
		return LicenseOptions{}, err
	}

	licenseCategories := make(map[types.LicenseCategory][]string)
	licenseCategories[types.CategoryForbidden] = f.LicenseForbidden.Value()
	licenseCategories[types.CategoryRestricted] = f.LicenseRestricted.Value()
	licenseCategories[types.CategoryReciprocal] = f.LicenseReciprocal.Value()
	licenseCategories[types.CategoryNotice] = f.LicenseNotice.Value()
	licenseCategories[types.CategoryPermissive] = f.LicensePermissive.Value()
	licenseCategories[types.CategoryUnencumbered] = f.LicenseUnencumbered.Value()

	return LicenseOptions{
		LicenseFull:            f.LicenseFull.Value(),
		IgnoredLicenses:        f.IgnoredLicenses.Value(),
		LicenseConfidenceLevel: f.LicenseConfidenceLevel.Value(),
		LicenseCategories:      licenseCategories,
		LicenseTextCacheDir:    f.LicenseTextCacheDir.Value(),
		LicenseScanWorkers:     f.LicenseScanWorkers.Value(),
	}, nil
}
