package config

import (
	"os"
	"time"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

// ArtifactConfig holds the config for a artifact scanning
type ArtifactConfig struct {
	Input      string
	Timeout    time.Duration
	ClearCache bool

	SkipDirs  []string
	SkipFiles []string

	// this field is populated in Init()
	Target string
}

// NewArtifactConfig is the factory method to return artifact config
func NewArtifactConfig(c *cli.Context) ArtifactConfig {
	return ArtifactConfig{
		Input:      c.String("input"),
		Timeout:    c.Duration("timeout"),
		ClearCache: c.Bool("clear-cache"),
		SkipFiles:  c.StringSlice("skip-files"),
		SkipDirs:   c.StringSlice("skip-dirs"),
	}
}

// Init initialize the CLI context for artifact scanning
func (c *ArtifactConfig) Init(ctx *cli.Context, logger *zap.SugaredLogger) (err error) {
	if c.Input == "" && ctx.Args().Len() == 0 {
		logger.Debug(`trivy requires at least 1 argument or --input option`)
		_ = cli.ShowSubcommandHelp(ctx) // nolint: errcheck
		os.Exit(0)
	} else if ctx.Args().Len() > 1 {
		logger.Error(`multiple targets cannot be specified`)
		return xerrors.New("arguments error")
	}

	if c.Input == "" {
		c.Target = ctx.Args().First()
	}

	return nil
}
