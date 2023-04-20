package flag

import (
	"golang.org/x/exp/slices"
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
	RuntimeFlag = Flag{
		Name:       "runtimes",
		ConfigName: "scan.runtimes",
		Value:      types.AllRuntimes.StringSlice(),
		Usage:      "Runtime(s) to use, in priority order (docker,containerd,podman,remote)",
	}
)

type ImageFlagGroup struct {
	Input               *Flag // local image archive
	ImageConfigScanners *Flag
	ScanRemovedPkgs     *Flag
	Platform            *Flag
	Runtimes            *Flag
}

type ImageOptions struct {
	Input               string
	ImageConfigScanners types.Scanners
	ScanRemovedPkgs     bool
	Platform            string
	Runtimes            types.Runtimes
}

func NewImageFlagGroup() *ImageFlagGroup {
	return &ImageFlagGroup{
		Input:               &InputFlag,
		ImageConfigScanners: &ImageConfigScannersFlag,
		ScanRemovedPkgs:     &ScanRemovedPkgsFlag,
		Platform:            &PlatformFlag,
		Runtimes:            &RuntimeFlag,
	}
}

func (f *ImageFlagGroup) Name() string {
	return "Image"
}

func (f *ImageFlagGroup) Flags() []*Flag {
	return []*Flag{f.Input, f.ImageConfigScanners, f.ScanRemovedPkgs, f.Platform, f.Runtimes}
}

func (f *ImageFlagGroup) ToOptions() (ImageOptions, error) {
	scanners, err := parseScanners(getStringSlice(f.ImageConfigScanners), types.AllImageConfigScanners)
	if err != nil {
		return ImageOptions{}, xerrors.Errorf("unable to parse image config scanners: %w", err)
	}

	runtimes, err := parseRuntimes(getStringSlice(f.Runtimes), types.AllRuntimes)
	if err != nil {
		return ImageOptions{}, xerrors.Errorf("unable to parse runtimes: %w", err)
	}

	return ImageOptions{
		Input:               getString(f.Input),
		ImageConfigScanners: scanners,
		ScanRemovedPkgs:     getBool(f.ScanRemovedPkgs),
		Platform:            getString(f.Platform),
		Runtimes:            runtimes,
	}, nil
}

func parseRuntimes(runtime []string, allowedRuntimes types.Runtimes) (types.Runtimes, error) {
	var runtimes types.Runtimes
	for _, v := range runtime {
		s := types.Runtime(v)
		if !slices.Contains(allowedRuntimes, s) {
			return nil, xerrors.Errorf("unknown runtime: %s", v)
		}
		runtimes = append(runtimes, s)
	}
	return runtimes, nil
}
