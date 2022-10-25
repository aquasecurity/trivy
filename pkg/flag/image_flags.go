package flag

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

	PlatformFlag = Flag{
		Name:       "platform",
		ConfigName: "image.platform",
		Value:      "",
		Usage:      "set platform in the form os/arch if image is multi-platform capable",
	}
)

type ImageFlagGroup struct {
	Input           *Flag // local image archive
	ScanRemovedPkgs *Flag
	Platform        *Flag
}

type ImageOptions struct {
	Input           string
	ScanRemovedPkgs bool
	Platform        string
}

func NewImageFlagGroup() *ImageFlagGroup {
	return &ImageFlagGroup{
		Input:           &InputFlag,
		ScanRemovedPkgs: &ScanRemovedPkgsFlag,
		Platform:        &PlatformFlag,
	}
}

func (f *ImageFlagGroup) Name() string {
	return "Image"
}

func (f *ImageFlagGroup) Flags() []*Flag {
	return []*Flag{f.Input, f.ScanRemovedPkgs, f.Platform}
}

func (f *ImageFlagGroup) ToOptions() ImageOptions {
	return ImageOptions{
		Input:           getString(f.Input),
		ScanRemovedPkgs: getBool(f.ScanRemovedPkgs),
		Platform:        getString(f.Platform),
	}
}
