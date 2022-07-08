package flag

import (
	"github.com/spf13/cobra"
)

// e.g. config yaml
// image:
//   removed-pkgs: true
//   input: "/path/to/alpine"

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

type ImageFlagGroup struct {
	Input           *Flag // local image archive
	ScanRemovedPkgs *Flag
}

type ImageOptions struct {
	Input           string
	ScanRemovedPkgs bool
}

func NewImageFlagGroup() *ImageFlagGroup {
	return &ImageFlagGroup{
		Input:           &InputFlag,
		ScanRemovedPkgs: &ScanRemovedPkgsFlag,
	}
}

func (f *ImageFlagGroup) flags() []*Flag {
	return []*Flag{f.Input, f.ScanRemovedPkgs}
}

func (f *ImageFlagGroup) AddFlags(cmd *cobra.Command) {
	for _, flag := range f.flags() {
		addFlag(cmd, flag)
	}
}

func (f *ImageFlagGroup) Bind(cmd *cobra.Command) error {
	for _, flag := range f.flags() {
		if err := bind(cmd, flag); err != nil {
			return err
		}
	}
	return nil
}

func (f *ImageFlagGroup) ToOptions() ImageOptions {
	return ImageOptions{
		Input:           getString(f.Input),
		ScanRemovedPkgs: getBool(f.ScanRemovedPkgs),
	}
}
