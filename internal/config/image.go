package config

import (
	"github.com/urfave/cli/v2"
)

// ImageConfig holds the config for scanning images
type ImageConfig struct {
	ScanRemovedPkgs bool
	ListAllPkgs     bool
}

// NewImageConfig is the factory method to return imageConfig
func NewImageConfig(c *cli.Context) ImageConfig {
	return ImageConfig{
		ScanRemovedPkgs: c.Bool("removed-pkgs"),
		ListAllPkgs:     c.Bool("list-all-pkgs"),
	}
}
