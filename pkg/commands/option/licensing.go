package option

import (
	"github.com/urfave/cli/v2"
)

// LicenseOption holds the options for license scanning
type LicenseOption struct {
	RiskThreshold   int
	IgnoredLicenses []string
}

// NewLicenseOption is the factory method to return licensing options
func NewLicenseOption(c *cli.Context) LicenseOption {
	return LicenseOption{
		RiskThreshold:   c.Int("license-risk-threshold"),
		IgnoredLicenses: c.StringSlice("ignored-licenses"),
	}
}
