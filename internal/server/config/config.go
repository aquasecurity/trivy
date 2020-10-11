package config

import (
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/trivy/internal/config"
)

// Config holds the  Trivy config
type Config struct {
	config.GlobalConfig
	config.DBConfig

	Listen      string
	Token       string
	TokenHeader string
}

// New is the factory method to return cofig
func New(c *cli.Context) Config {
	// the error is ignored because logger is unnecessary
	gc, err := config.NewGlobalConfig(c)
	if err != nil {
		fmt.Printf("error creating globalConfig: %v", err)
	}
	return Config{
		GlobalConfig: gc,
		DBConfig:     config.NewDBConfig(c),

		Listen:      c.String("listen"),
		Token:       c.String("token"),
		TokenHeader: c.String("token-header"),
	}
}

// Init initializes the DB config
func (c *Config) Init() (err error) {
	if err := c.DBConfig.Init(); err != nil {
		return err
	}

	return nil
}
