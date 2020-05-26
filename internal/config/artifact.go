package config

import (
	"time"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

type ArtifactConfig struct {
	Input      string
	Timeout    time.Duration
	ClearCache bool

	// this field is populated in Init()
	Target string
}

func NewArtifactConfig(c *cli.Context) ArtifactConfig {
	return ArtifactConfig{
		Input:      c.String("input"),
		Timeout:    c.Duration("timeout"),
		ClearCache: c.Bool("clear-cache"),
	}
}

func (c *ArtifactConfig) Init(args cli.Args, logger *zap.SugaredLogger) (err error) {
	if c.Input == "" && args.Len() == 0 {
		logger.Error(`trivy requires at least 1 argument or --input option`)
		return xerrors.New("arguments error")
	} else if args.Len() > 1 {
		logger.Error(`multiple targets cannot be specified`)
		return xerrors.New("arguments error")
	}

	if c.Input == "" {
		c.Target = args.First()
	}

	return nil
}
