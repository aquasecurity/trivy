package config

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/internal/config"
)

type Config struct {
	config.GlobalConfig
	config.ArtifactConfig
	config.DBConfig
	config.ImageConfig
	config.ReportConfig

	// deprecated
	onlyUpdate string
	// deprecated
	refresh bool
	// deprecated
	autoRefresh bool
}

func New(c *cli.Context) (Config, error) {
	gc, err := config.NewGlobalConfig(c)
	if err != nil {
		return Config{}, xerrors.Errorf("failed to initialize global options: %w", err)
	}

	return Config{
		GlobalConfig:   gc,
		ArtifactConfig: config.NewArtifactConfig(c),
		DBConfig:       config.NewDBConfig(c),
		ImageConfig:    config.NewImageConfig(c),
		ReportConfig:   config.NewReportConfig(c),

		onlyUpdate:  c.String("only-update"),
		refresh:     c.Bool("refresh"),
		autoRefresh: c.Bool("auto-refresh"),
	}, nil
}

func (c *Config) Init(image bool) error {
	if err := c.ReportConfig.Init(c.Logger); err != nil {
		return err
	}
	if c.onlyUpdate != "" || c.refresh || c.autoRefresh {
		c.Logger.Warn("--only-update, --refresh and --auto-refresh are unnecessary and ignored now. These commands will be removed in the next version.")
	}
	if err := c.DBConfig.Init(); err != nil {
		return err
	}

	// --clear-cache, --download-db-only and --reset don't conduct the scan
	if c.ClearCache || c.DownloadDBOnly || c.Reset {
		return nil
	}

	if err := c.ArtifactConfig.Init(c.Context, c.Logger); err != nil {
		return err
	}

	if image {
		if err := c.ImageConfig.Init(c.Context.Args(), c.Logger); err != nil {
			return err
		}
	}

	return nil
}
