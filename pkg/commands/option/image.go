package option

import (
	"github.com/urfave/cli/v2"
)

// ImageOption holds the options for scanning images
type ImageOption struct {
	ScanRemovedPkgs bool
}

// NewImageOption is the factory method to return ImageOption
func NewImageOption(c *cli.Context) ImageOption {
	return ImageOption{
		ScanRemovedPkgs: c.Bool("removed-pkgs"),
	}
}
