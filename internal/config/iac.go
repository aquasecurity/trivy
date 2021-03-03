package config

import (
	"github.com/urfave/cli/v2"
)

// IaCConfig holds the config for IaC scanning
type IaCConfig struct {
	IaCPolicy []string
	IaCData   []string
}

// NewIaCConfig is the factory method to return IaC config
func NewIaCConfig(c *cli.Context) IaCConfig {
	return IaCConfig{
		IaCPolicy: c.StringSlice("iac-policy"),
		IaCData:   c.StringSlice("iac-data"),
	}
}
