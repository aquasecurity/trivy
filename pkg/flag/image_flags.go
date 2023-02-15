package flag

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/types"
)

// e.g. config yaml
// image:
//   removed-pkgs: true
//   input: "/path/to/alpine"

var (
	ImageConfigScannersFlag = Flag{
		Name:       "image-config-scanners",
		ConfigName: "image.image-config-scanners",
		Value:      "",
		Usage:      "comma-separated list of what security issues to detect on container image configurations (config,secret)",
	}
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
	PlatformFlag = Flag{
		Name:       "platform",
		ConfigName: "image.platform",
		Value:      "",
		Usage:      "set platform in the form os/arch if image is multi-platform capable",
	}
)

type ImageFlagGroup struct {
	Input               *Flag // local image archive
	ImageConfigScanners *Flag
	ScanRemovedPkgs     *Flag
	Platform            *Flag
}

type ImageOptions struct {
	Input               string
	ImageConfigScanners types.Scanners
	ScanRemovedPkgs     bool
	Platform            string
}

func NewImageFlagGroup() *ImageFlagGroup {
	return &ImageFlagGroup{
		Input:               &InputFlag,
		ImageConfigScanners: &ImageConfigScannersFlag,
		ScanRemovedPkgs:     &ScanRemovedPkgsFlag,
		Platform:            &PlatformFlag,
	}
}

func (f *ImageFlagGroup) Name() string {
	return "Image"
}

func (f *ImageFlagGroup) Flags() []*Flag {
	return []*Flag{f.Input, f.ImageConfigScanners, f.ScanRemovedPkgs, f.Platform}
}

func (f *ImageFlagGroup) ToOptions() (ImageOptions, error) {
	scanners, err := parseScanners(getStringSlice(f.ImageConfigScanners), types.AllImageConfigScanners)
	if err != nil {
		return ImageOptions{}, xerrors.Errorf("unable to parse image config scanners: %w", err)
	}
	return ImageOptions{
		Input:               getString(f.Input),
		ImageConfigScanners: scanners,
		ScanRemovedPkgs:     getBool(f.ScanRemovedPkgs),
		Platform:            getString(f.Platform),
	}, nil
}
