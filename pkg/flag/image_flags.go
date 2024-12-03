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
	ImageConfigScannersFlag = Flag[[]string]{
		Name:       "image-config-scanners",
		ConfigName: "image.image-config-scanners",
		Values: xstrings.ToStringSlice(types.Scanners{
			types.MisconfigScanner,
			types.SecretScanner,
		}),
		Usage: "comma-separated list of what security issues to detect on container image configurations",
	}
	ScanRemovedPkgsFlag = Flag[bool]{
		Name:       "removed-pkgs",
		ConfigName: "image.removed-pkgs",
		Usage:      "detect vulnerabilities of removed packages (only for Alpine)",
	}
	InputFlag = Flag[string]{
		Name:       "input",
		ConfigName: "image.input",
		Usage:      "input file path instead of image name",
	}
	PlatformFlag = Flag[string]{
		Name:       "platform",
		ConfigName: "image.platform",
		Usage:      "set platform in the form os/arch if image is multi-platform capable",
	}
	DockerHostFlag = Flag[string]{
		Name:       "docker-host",
		ConfigName: "image.docker.host",
		Default:    "",
		Usage:      "unix domain socket path to use for docker scanning",
	}
	PodmanHostFlag = Flag[string]{
		Name:       "podman-host",
		ConfigName: "image.podman.host",
		Default:    "",
		Usage:      "unix podman socket path to use for podman scanning",
	}
	SourceFlag = Flag[[]string]{
		Name:       "image-src",
		ConfigName: "image.source",
		Default:    xstrings.ToStringSlice(ftypes.AllImageSources),
		Values:     xstrings.ToStringSlice(ftypes.AllImageSources),
		Usage:      "image source(s) to use, in priority order",
	}
)

type ImageFlagGroup struct {
	Input               *Flag[string] // local image archive
	ImageConfigScanners *Flag[[]string]
	ScanRemovedPkgs     *Flag[bool]
	Platform            *Flag[string]
	DockerHost          *Flag[string]
	PodmanHost          *Flag[string]
	ImageSources        *Flag[[]string]
}

type ImageOptions struct {
	Input               string
	ImageConfigScanners types.Scanners
	ScanRemovedPkgs     bool
	Platform            ftypes.Platform
	DockerHost          string
	PodmanHost          string
	ImageSources        ftypes.ImageSources
}

func NewImageFlagGroup() *ImageFlagGroup {
	return &ImageFlagGroup{
		Input:               InputFlag.Clone(),
		ImageConfigScanners: ImageConfigScannersFlag.Clone(),
		ScanRemovedPkgs:     ScanRemovedPkgsFlag.Clone(),
		Platform:            PlatformFlag.Clone(),
		DockerHost:          DockerHostFlag.Clone(),
		PodmanHost:          PodmanHostFlag.Clone(),
		ImageSources:        SourceFlag.Clone(),
	}
}

func (f *ImageFlagGroup) Name() string {
	return "Image"
}

func (f *ImageFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.Input,
		f.ImageConfigScanners,
		f.ScanRemovedPkgs,
		f.Platform,
		f.DockerHost,
		f.PodmanHost,
		f.ImageSources,
	}
}

func (f *ImageFlagGroup) ToOptions() (ImageOptions, error) {
	if err := parseFlags(f); err != nil {
		return ImageOptions{}, err
	}

	var platform ftypes.Platform
	if p := f.Platform.Value(); p != "" {
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
		Input:               f.Input.Value(),
		ImageConfigScanners: xstrings.ToTSlice[types.Scanner](f.ImageConfigScanners.Value()),
		ScanRemovedPkgs:     f.ScanRemovedPkgs.Value(),
		Platform:            platform,
		DockerHost:          f.DockerHost.Value(),
		PodmanHost:          f.PodmanHost.Value(),
		ImageSources:        xstrings.ToTSlice[ftypes.ImageSource](f.ImageSources.Value()),
	}, nil
}
