package config

import (
	"net/http"
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/internal/config"
)

type Config struct {
	config.GlobalConfig
	config.ArtifactConfig
	config.ImageConfig
	config.ReportConfig

	RemoteAddr    string
	token         string
	tokenHeader   string
	customHeaders []string

	// this field is populated in Init()
	CustomHeaders http.Header
}

func New(c *cli.Context) (Config, error) {
	gc, err := config.NewGlobalConfig(c)
	if err != nil {
		return Config{}, xerrors.Errorf("failed to initialize global options: %w", err)
	}

	return Config{
		GlobalConfig:   gc,
		ArtifactConfig: config.NewArtifactConfig(c),
		ImageConfig:    config.NewImageConfig(c),
		ReportConfig:   config.NewReportConfig(c),
		RemoteAddr:     c.String("remote"),
		token:          c.String("token"),
		tokenHeader:    c.String("token-header"),
		customHeaders:  c.StringSlice("custom-headers"),
	}, nil
}

func (c *Config) Init() (err error) {
	// --clear-cache doesn't conduct the scan
	if c.ClearCache {
		return nil
	}

	c.CustomHeaders = splitCustomHeaders(c.customHeaders)

	// add token to custom headers
	if c.token != "" {
		c.CustomHeaders.Set(c.tokenHeader, c.token)
	}

	if err := c.ReportConfig.Init(c.Logger); err != nil {
		return err
	}

	if err := c.ArtifactConfig.Init(c.Context.Args(), c.Logger); err != nil {
		return err
	}

	if err := c.ImageConfig.Init(c.Context.Args(), c.Logger); err != nil {
		cli.ShowAppHelp(c.Context)
		return err
	}

	return nil
}

func splitCustomHeaders(headers []string) http.Header {
	result := make(http.Header)
	for _, header := range headers {
		// e.g. x-api-token:XXX
		s := strings.SplitN(header, ":", 2)
		if len(s) != 2 {
			continue
		}
		result.Set(s[0], s[1])
	}
	return result
}
