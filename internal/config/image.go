package config

import (
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

type ImageConfig struct {
	ScanRemovedPkgs bool
	ListAllPkgs     bool
}

func NewImageConfig(c *cli.Context) ImageConfig {
	return ImageConfig{
		ScanRemovedPkgs: c.Bool("removed-pkgs"),
		ListAllPkgs:     c.Bool("list-all-pkgs"),
	}
}

func (c *ImageConfig) Init(args cli.Args, logger *zap.SugaredLogger) (err error) {
	imageName := args.First()

	// Check whether 'latest' tag is used
	if imageName != "" {
		ref, err := name.ParseReference(imageName)
		if err != nil {
			return xerrors.Errorf("invalid image: %w", err)
		}
		if ref.Identifier() == "latest" {
			logger.Warn("You should avoid using the :latest tag as it is cached. You need to specify '--clear-cache' option when :latest image is changed")
		}
	}

	return nil
}
