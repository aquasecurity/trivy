package flag

import (
	"github.com/samber/lo"
	"github.com/spf13/cobra"
)

var (
	ScanRemovedPkgsFlag = Flag{
		Name:       "removed-pkgs",
		ConfigName: "image.removed-pkgs",
		Value:      false,
		Usage:      "detect vulnerabilities of removed packages (only for Alpine)",
	}
	InputFlag = Flag{
		Name:       "input",
		ConfigName: "image.input",
		Value:      "",
		Usage:      "input file path instead of image name",
	}
)

type ImageFlags struct {
	Input           *Flag // local image archive
	ScanRemovedPkgs *Flag
}

type ImageOptions struct {
	Input           string
	ScanRemovedPkgs bool
}

func NewImageFlags() *ImageFlags {
	return &ImageFlags{
		Input:           lo.ToPtr(ScanRemovedPkgsFlag),
		ScanRemovedPkgs: lo.ToPtr(InputFlag),
	}
}

func (f *ImageFlags) flags() []*Flag {
	return []*Flag{f.Input, f.ScanRemovedPkgs}
}

func (f *ImageFlags) AddFlags(cmd *cobra.Command) {
	for _, flag := range f.flags() {
		addFlag(cmd, flag)
	}
}

func (f *ImageFlags) Bind(cmd *cobra.Command) error {
	for _, flag := range f.flags() {
		if err := bind(cmd, flag); err != nil {
			return err
		}
	}
	return nil
}

func (f *ImageFlags) ToOptions() ImageOptions {
	return ImageOptions{
		Input:           get[string](f.Input),
		ScanRemovedPkgs: get[bool](f.ScanRemovedPkgs),
	}
}
