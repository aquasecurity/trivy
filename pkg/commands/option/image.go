package option

import (
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
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
func (io *ImageOption) InitByFormat(format string, logger *zap.SugaredLogger) {
	if format == "gsbom" {
		logger.Info("--format gsbom is specified, all packages will be returned.")

		io.ListAllPkgs = true
	}

}
