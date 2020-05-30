package config

import (
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

type ImageConfig struct {
	Input           string
	ScanRemovedPkgs bool
	Timeout         time.Duration
	ClearCache      bool

	// this field is populated in Init()
	ImageName string
}

func NewImageConfig(c *cli.Context) ImageConfig {
	return ImageConfig{
		Input:           c.String("input"),
		ScanRemovedPkgs: c.Bool("removed-pkgs"),
		Timeout:         c.Duration("timeout"),
		ClearCache:      c.Bool("clear-cache"),
	}
}

func (c *ImageConfig) Init(args cli.Args, logger *zap.SugaredLogger) (err error) {
	if c.Input == "" && args.Len() == 0 {
		logger.Error(`trivy requires at least 1 argument or --input option`)
		return xerrors.New("arguments error")
	} else if args.Len() > 1 {
		logger.Error(`multiple images cannot be specified`)
		return xerrors.New("arguments error")
	}

	if c.Input == "" {
		c.ImageName = args.First()
	}

	// Check whether 'latest' tag is used
	if c.ImageName != "" {
		ref, err := name.ParseReference(c.ImageName)
		if err != nil {
			return xerrors.Errorf("invalid image: %w", err)
		}
		if ref.Identifier() == "latest" {
			logger.Warn("You should avoid using the :latest tag as it is cached. You need to specify '--clear-cache' option when :latest image is changed")
		}
	}

	return nil
}
