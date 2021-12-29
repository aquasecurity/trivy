package server

import (
	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/trivy/pkg/commands/option"
)

// Config holds the Trivy config
type Config struct {
	option.GlobalOption
	option.DBOption
	option.CacheOption

	Listen      string
	Token       string
	TokenHeader string
}

// NewConfig is the factory method to return config
func NewConfig(c *cli.Context) Config {
	// the error is ignored because logger is unnecessary
	gc, _ := option.NewGlobalOption(c) // nolint: errcheck
	return Config{
		GlobalOption: gc,
		DBOption:     option.NewDBOption(c),
		CacheOption:  option.NewCacheOption(c),

		Listen:      c.String("listen"),
		Token:       c.String("token"),
		TokenHeader: c.String("token-header"),
	}
}

// Init initializes the config
func (c *Config) Init() (err error) {
	if err := c.DBOption.Init(); err != nil {
		return err
	}
	if err := c.CacheOption.Init(); err != nil {
		return err
	}

	return nil
}
