package flag

import (
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
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
	DockerHostFlag = Flag{
		Name:       "docker-host",
		ConfigName: "image.docker.host",
		Value:      "",
		Usage:      "unix domain socket path to use for docker scanning",
	}
	SourceFlag = Flag{
		Name:       "image-src",
		ConfigName: "image.source",
		Value:      ftypes.AllImageSources.StringSlice(),
		Usage:      "image source(s) to use, in priority order (docker,containerd,podman,remote)",
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
	Platform            string
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
	scanners, err := parseScanners(getStringSlice(f.ImageConfigScanners), types.AllImageConfigScanners)
	if err != nil {
		return ImageOptions{}, xerrors.Errorf("unable to parse image config scanners: %w", err)
	}

	imageSources, err := parseImageSources(getStringSlice(f.ImageSources), ftypes.AllImageSources)
	if err != nil {
		return ImageOptions{}, xerrors.Errorf("unable to parse runtimes: %w", err)
	}

	return ImageOptions{
		Input:               getString(f.Input),
		ImageConfigScanners: scanners,
		ScanRemovedPkgs:     getBool(f.ScanRemovedPkgs),
		Platform:            getString(f.Platform),
		DockerHost:          getString(f.DockerHost),
		ImageSources:        imageSources,
	}, nil
}

func parseImageSources(runtime []string, allowedImageSources ftypes.ImageSources) (ftypes.ImageSources, error) {
	var imageSources ftypes.ImageSources
	for _, v := range runtime {
		s := ftypes.ImageSource(v)
		if !slices.Contains(allowedImageSources, s) {
			return nil, xerrors.Errorf("unknown runtime: %s", v)
		}
		imageSources = append(imageSources, s)
	}
	return imageSources, nil
}
