package config

import (
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

// GlobalConfig holds the global config for trivy
type GlobalConfig struct {
	Context *cli.Context
	Logger  *zap.SugaredLogger

	AppVersion string
	Quiet      bool
	Debug      bool
	CacheDir   string
}

// NewGlobalConfig is the factory method to return GlobalConfig
func NewGlobalConfig(c *cli.Context) (GlobalConfig, error) {
	quiet := c.Bool("quiet")
	debug := c.Bool("debug")
	logger, err := log.NewLogger(debug, quiet)
	if err != nil {
		return GlobalConfig{}, xerrors.New("failed to create a logger")
	}

	return GlobalConfig{
		Context: c,
		Logger:  logger,

		AppVersion: c.App.Version,
		Quiet:      quiet,
		Debug:      debug,
		CacheDir:   c.String("cache-dir"),
	}, nil
}
