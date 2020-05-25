package config

import (
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

type GlobalConfig struct {
	Context *cli.Context
	Logger  *zap.SugaredLogger

	AppVersion string
	Quiet      bool
	Debug      bool
	CacheDir   string
}

func NewGlobalConfig(c *cli.Context) (GlobalConfig, error) {
	quiet := c.Bool("quiet")
	debug := c.Bool("debug")
	logger, err := log.NewLogger(quiet, debug)
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
