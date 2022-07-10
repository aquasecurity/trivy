package flag

var (
	IgnoredLicenses = Flag{
		Name:       "ignored-licenses",
		ConfigName: "license.ignored",
		Value:      []string{},
		Usage:      "specify a list of license to ignore",
	}
	LicenseRiskThreshold = Flag{
		Name:       "license-risk-threshold",
		ConfigName: "license.risk-threshold",
		Value:      4,
		Usage:      "specify the threshold of license risk to report on",
	}
)

type LicenseFlagGroup struct {
	IgnoredLicenses      *Flag
	LicenseRiskThreshold *Flag
}

type LicenseOptions struct {
	IgnoredLicenses      []string
	LicenseRiskThreshold int
}

func NewLicenseFlagGroup() *LicenseFlagGroup {
	return &LicenseFlagGroup{
		IgnoredLicenses:      &IgnoredLicenses,
		LicenseRiskThreshold: &LicenseRiskThreshold,
	}
}

func (f *LicenseFlagGroup) Name() string {
	return "License"
}

func (f *LicenseFlagGroup) Flags() []*Flag {
	return []*Flag{f.IgnoredLicenses, f.LicenseRiskThreshold}
}

func (f *LicenseFlagGroup) ToOptions() LicenseOptions {
	return LicenseOptions{
		IgnoredLicenses:      getStringSlice(f.IgnoredLicenses),
		LicenseRiskThreshold: getInt(f.LicenseRiskThreshold),
	}
}
