package config

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/internal/config"
)

// Config holds the artifact config
type Config struct {
	config.GlobalConfig
	config.ArtifactConfig
	config.DBConfig
	config.ImageConfig
	config.ReportConfig
	config.CacheConfig

	// deprecated
	onlyUpdate string
	// deprecated
	refresh bool
	// deprecated
	autoRefresh bool
}

// New is the factory method to return config
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
		CacheConfig:    config.NewCacheConfig(c),

		onlyUpdate:  c.String("only-update"),
		refresh:     c.Bool("refresh"),
		autoRefresh: c.Bool("auto-refresh"),
	}, nil
}

// Init initializes the artifact config
func (c *Config) Init(image bool) error {
	if c.onlyUpdate != "" || c.refresh || c.autoRefresh {
		c.Logger.Warn("--only-update, --refresh and --auto-refresh are unnecessary and ignored now. These commands will be removed in the next version.")
	}

	if err := c.initPreScanConfigs(); err != nil {
		return err
	}

	// --clear-cache, --download-db-only and --reset don't conduct the scan
	if c.skipScan() {
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

func (c *Config) initPreScanConfigs() error {
	if err := c.ReportConfig.Init(c.Logger); err != nil {
		return err
	}
	if err := c.DBConfig.Init(); err != nil {
		return err
	}
	if err := c.CacheConfig.Init(); err != nil {
		return err
	}
	return nil
}

func (c *Config) skipScan() bool {
	if c.ClearCache || c.DownloadDBOnly || c.Reset {
		return true
	}
	return false
}
