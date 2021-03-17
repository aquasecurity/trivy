package option

import (
	"github.com/urfave/cli/v2"
)

// ConfigOption holds the options for config scanning
type ConfigOption struct {
	OPAPolicy []string
	OPAData   []string
}

// NewConfigOption is the factory method to return config scanning options
func NewConfigOption(c *cli.Context) ConfigOption {
	return ConfigOption{
		OPAPolicy: c.StringSlice("config-policy"),
		OPAData:   c.StringSlice("config-data"),
	}
}
