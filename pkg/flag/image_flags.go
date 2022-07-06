package flag

import (
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	ScanRemovedPkgsFlag = "removed-pkgs"
	InputFlag           = "input"
)

type ImageFlags struct {
	Input           *string // local image archive
	ScanRemovedPkgs *bool
}

type ImageOptions struct {
	Input           string
	ScanRemovedPkgs bool
}

func NewImageFlags() *ImageFlags {
	return &ImageFlags{
		Input:           lo.ToPtr(""),
		ScanRemovedPkgs: lo.ToPtr(false),
	}
}

func (f *ImageFlags) AddFlags(cmd *cobra.Command) {
	if f.Input != nil {
		cmd.Flags().String(InputFlag, *f.Input, "input file path instead of image name")
	}
	if f.ScanRemovedPkgs != nil {
		cmd.Flags().Bool(ScanRemovedPkgsFlag, *f.ScanRemovedPkgs, "detect vulnerabilities of removed packages (only for Alpine)")
	}
}

func (f *ImageFlags) ToOptions() ImageOptions {
	return ImageOptions{
		Input:           viper.GetString(InputFlag),
		ScanRemovedPkgs: viper.GetBool(ScanRemovedPkgsFlag),
	}
}
