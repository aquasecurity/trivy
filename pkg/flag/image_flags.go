package flag

import (
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const ScanRemovedPkgsFlag = "removed-pkgs"

type ImageFlags struct {
	ScanRemovedPkgs *bool
}

type ImageOptions struct {
	ScanRemovedPkgs bool
}

func NewImageDefaultFlags() *ImageFlags {
	return &ImageFlags{
		ScanRemovedPkgs: lo.ToPtr(false),
	}
}

func (f *ImageFlags) AddFlags(cmd *cobra.Command) {
	if f.ScanRemovedPkgs != nil {
		cmd.Flags().Bool(ScanRemovedPkgsFlag, *f.ScanRemovedPkgs, "detect vulnerabilities of removed packages (only for Alpine)")
	}
}

func (f *ImageFlags) ToOptions() ImageOptions {
	return ImageOptions{
		ScanRemovedPkgs: viper.GetBool(ScanRemovedPkgsFlag),
	}
}
