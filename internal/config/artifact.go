package config

import (
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

type ArtifactConfig struct {
	Input      string
	Timeout    time.Duration
	ClearCache bool

	skipDirectories string
	SkipDirectories []string
	skipFiles       string
	SkipFiles       []string

	// this field is populated in Init()
	Target string
}

func NewArtifactConfig(c *cli.Context) ArtifactConfig {
	return ArtifactConfig{
		Input:           c.String("input"),
		Timeout:         c.Duration("timeout"),
		ClearCache:      c.Bool("clear-cache"),
		skipFiles:       c.String("skip-files"),
		skipDirectories: c.String("skip-dirs"),
	}
}

func (c *ArtifactConfig) Init(ctx *cli.Context, logger *zap.SugaredLogger) (err error) {
	if c.Input == "" && ctx.Args().Len() == 0 {
		logger.Debug(`trivy requires at least 1 argument or --input option`)
		_ = cli.ShowSubcommandHelp(ctx)
		os.Exit(0)
	} else if ctx.Args().Len() > 1 {
		logger.Error(`multiple targets cannot be specified`)
		return xerrors.New("arguments error")
	}

	if c.Input == "" {
		c.Target = ctx.Args().First()
	}

	if c.skipDirectories != "" {
		c.SkipDirectories = strings.Split(c.skipDirectories, ",")
	}

	if c.skipFiles != "" {
		c.SkipFiles = strings.Split(c.skipFiles, ",")
	}

	return nil
}
