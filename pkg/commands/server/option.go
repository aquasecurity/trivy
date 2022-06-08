package server

import (
	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/trivy/pkg/commands/option"
)

// Option holds the Trivy config
type Option struct {
	option.GlobalOption
	option.DBOption
	option.CacheOption
	option.OtherOption

	Listen      string
	Token       string
	TokenHeader string
}

// NewOption is the factory method to return config
func NewOption(c *cli.Context) Option {
	// the error is ignored because logger is unnecessary
	gc, _ := option.NewGlobalOption(c) // nolint: errcheck
	return Option{
		GlobalOption: gc,
		DBOption:     option.NewDBOption(c),
		CacheOption:  option.NewCacheOption(c),
		OtherOption:  option.NewOtherOption(c),

		Listen:      c.String("listen"),
		Token:       c.String("token"),
		TokenHeader: c.String("token-header"),
	}
}

// Init initializes the config
func (c *Option) Init() (err error) {
	if err := c.DBOption.Init(); err != nil {
		return err
	}
	if err := c.CacheOption.Init(); err != nil {
		return err
	}

	return nil
}
