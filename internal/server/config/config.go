package config

import (
	"github.com/aquasecurity/trivy/internal/config"
	"github.com/urfave/cli/v2"
)

type Config struct {
	config.GlobalConfig
	config.DBConfig

	Listen      string
	Token       string
	TokenHeader string
}

func New(c *cli.Context) Config {
	// the error is ignored because logger is unnecessary
	gc, _ := config.NewGlobalConfig(c)

	return Config{
		GlobalConfig: gc,
		DBConfig:     config.NewDBConfig(c),

		Listen:      c.String("listen"),
		Token:       c.String("token"),
		TokenHeader: c.String("token-header"),
	}
}

func (c *Config) Init() (err error) {
	if err := c.DBConfig.Init(); err != nil {
		return err
	}

	return nil
}
