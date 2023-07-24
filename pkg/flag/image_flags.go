package flag

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
)

// e.g. config yaml
// image:
//   removed-pkgs: true
//   input: "/path/to/alpine"

var (
	ImageConfigScannersFlag = Flag{
		Name:       "image-config-scanners",
		ConfigName: "image.image-config-scanners",
		Default:    []string{},
		Values: xstrings.ToStringSlice(types.Scanners{
			types.MisconfigScanner,
			types.SecretScanner,
		}),
		Usage: "comma-separated list of what security issues to detect on container image configurations",
	}
	ScanRemovedPkgsFlag = Flag{
		Name:       "removed-pkgs",
		ConfigName: "image.removed-pkgs",
		Default:    false,
		Usage:      "detect vulnerabilities of removed packages (only for Alpine)",
	}
	InputFlag = Flag{
		Name:       "input",
		ConfigName: "image.input",
		Default:    "",
		Usage:      "input file path instead of image name",
	}
	PlatformFlag = Flag{
		Name:       "platform",
		ConfigName: "image.platform",
		Default:    "",
		Usage:      "set platform in the form os/arch if image is multi-platform capable",
	}
	DockerHostFlag = Flag{
		Name:       "docker-host",
		ConfigName: "image.docker.host",
		Default:    "",
		Usage:      "unix domain socket path to use for docker scanning",
	}
	SourceFlag = Flag{
		Name:       "image-src",
		ConfigName: "image.source",
		Default:    xstrings.ToStringSlice(ftypes.AllImageSources),
		Values:     xstrings.ToStringSlice(ftypes.AllImageSources),
		Usage:      "image source(s) to use, in priority order",
	}
)

type ImageFlagGroup struct {
	Input               *Flag // local image archive
	ImageConfigScanners *Flag
	ScanRemovedPkgs     *Flag
	Platform            *Flag
	DockerHost          *Flag
	ImageSources        *Flag
}

type ImageOptions struct {
	Input               string
	ImageConfigScanners types.Scanners
	ScanRemovedPkgs     bool
	Platform            ftypes.Platform
	DockerHost          string
	ImageSources        ftypes.ImageSources
}

func NewImageFlagGroup() *ImageFlagGroup {
	return &ImageFlagGroup{
		Input:               &InputFlag,
		ImageConfigScanners: &ImageConfigScannersFlag,
		ScanRemovedPkgs:     &ScanRemovedPkgsFlag,
		Platform:            &PlatformFlag,
		DockerHost:          &DockerHostFlag,
		ImageSources:        &SourceFlag,
	}
}

func (f *ImageFlagGroup) Name() string {
	return "Image"
}

func (f *ImageFlagGroup) Flags() []*Flag {
	return []*Flag{
		f.Input,
		f.ImageConfigScanners,
		f.ScanRemovedPkgs,
		f.Platform,
		f.DockerHost,
		f.ImageSources,
	}
}

func (f *ImageFlagGroup) ToOptions() (ImageOptions, error) {
	var platform ftypes.Platform
	if p := getString(f.Platform); p != "" {
		pl, err := v1.ParsePlatform(p)
		if err != nil {
			return ImageOptions{}, xerrors.Errorf("unable to parse platform: %w", err)
		}
		if pl.OS == "*" {
			pl.OS = "" // Empty OS means any OS
		}
		platform = ftypes.Platform{Platform: pl}
	}

	return ImageOptions{
		Input:               getString(f.Input),
		ImageConfigScanners: getUnderlyingStringSlice[types.Scanner](f.ImageConfigScanners),
		ScanRemovedPkgs:     getBool(f.ScanRemovedPkgs),
		Platform:            platform,
		DockerHost:          getString(f.DockerHost),
		ImageSources:        getUnderlyingStringSlice[ftypes.ImageSource](f.ImageSources),
	}, nil
}
