package config

import (
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

var ErrNoTarget = xerrors.New("no target is specified")

func (c *ArtifactConfig) Init(args cli.Args, logger *zap.SugaredLogger) (err error) {
	if c.Input == "" && args.Len() == 0 {
		logger.Debug(`trivy requires at least 1 argument or --input option`)
		return ErrNoTarget
	} else if args.Len() > 1 {
		logger.Error(`multiple targets cannot be specified`)
		return xerrors.New("arguments error")
	}

	if c.Input == "" {
		c.Target = args.First()
	}

	if c.skipDirectories != "" {
		c.SkipDirectories = strings.Split(c.skipDirectories, ",")
	}

	if c.skipFiles != "" {
		c.SkipFiles = strings.Split(c.skipFiles, ",")
	}

	return nil
}
