package flag

import (
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

var (
	ConfigFileFlag = Flag[string]{
		Name:       "config",
		ConfigName: "config",
		Shorthand:  "c",
		Default:    "trivy.yaml",
		Usage:      "config path",
		Persistent: true,
	}
	ShowVersionFlag = Flag[bool]{
		Name:       "version",
		ConfigName: "version",
		Shorthand:  "v",
		Usage:      "show version",
		Persistent: true,
	}
	QuietFlag = Flag[bool]{
		Name:       "quiet",
		ConfigName: "quiet",
		Shorthand:  "q",
		Usage:      "suppress progress bar and log output",
		Persistent: true,
	}
	DebugFlag = Flag[bool]{
		Name:       "debug",
		ConfigName: "debug",
		Shorthand:  "d",
		Usage:      "debug mode",
		Persistent: true,
	}
	InsecureFlag = Flag[bool]{
		Name:       "insecure",
		ConfigName: "insecure",
		Usage:      "allow insecure server connections",
		Persistent: true,
	}
	TimeoutFlag = Flag[time.Duration]{
		Name:       "timeout",
		ConfigName: "timeout",
		Default:    time.Second * 300, // 5 mins
		Usage:      "timeout",
		Persistent: true,
	}
	CacheDirFlag = Flag[string]{
		Name:       "cache-dir",
		ConfigName: "cache.dir",
		Default:    fsutils.CacheDir(),
		Usage:      "cache directory",
		Persistent: true,
	}
	GenerateDefaultConfigFlag = Flag[bool]{
		Name:       "generate-default-config",
		ConfigName: "generate-default-config",
		Usage:      "write the default config to trivy-default.yaml",
		Persistent: true,
	}
)

// GlobalFlagGroup composes global flags
type GlobalFlagGroup struct {
	ConfigFile            *Flag[string]
	ShowVersion           *Flag[bool] // spf13/cobra can't override the logic of version printing like VersionPrinter in urfave/cli. -v needs to be defined ourselves.
	Quiet                 *Flag[bool]
	Debug                 *Flag[bool]
	Insecure              *Flag[bool]
	Timeout               *Flag[time.Duration]
	CacheDir              *Flag[string]
	GenerateDefaultConfig *Flag[bool]
}

// GlobalOptions defines flags and other configuration parameters for all the subcommands
type GlobalOptions struct {
	ConfigFile            string
	ShowVersion           bool
	Quiet                 bool
	Debug                 bool
	Insecure              bool
	Timeout               time.Duration
	CacheDir              string
	GenerateDefaultConfig bool
}

func NewGlobalFlagGroup() *GlobalFlagGroup {
	return &GlobalFlagGroup{
		ConfigFile:            ConfigFileFlag.Clone(),
		ShowVersion:           ShowVersionFlag.Clone(),
		Quiet:                 QuietFlag.Clone(),
		Debug:                 DebugFlag.Clone(),
		Insecure:              InsecureFlag.Clone(),
		Timeout:               TimeoutFlag.Clone(),
		CacheDir:              CacheDirFlag.Clone(),
		GenerateDefaultConfig: GenerateDefaultConfigFlag.Clone(),
	}
}

func (f *GlobalFlagGroup) Name() string {
	return "global"
}

func (f *GlobalFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.ConfigFile,
		f.ShowVersion,
		f.Quiet,
		f.Debug,
		f.Insecure,
		f.Timeout,
		f.CacheDir,
		f.GenerateDefaultConfig,
	}
}

func (f *GlobalFlagGroup) AddFlags(cmd *cobra.Command) {
	for _, flag := range f.Flags() {
		flag.Add(cmd)
	}
}

func (f *GlobalFlagGroup) Bind(cmd *cobra.Command) error {
	for _, flag := range f.Flags() {
		if err := flag.Bind(cmd); err != nil {
			return err
		}
	}
	return nil
}

func (f *GlobalFlagGroup) ToOptions() (GlobalOptions, error) {
	if err := parseFlags(f); err != nil {
		return GlobalOptions{}, err
	}

	// Keep TRIVY_NON_SSL for backward compatibility
	insecure := f.Insecure.Value() || os.Getenv("TRIVY_NON_SSL") != ""

	return GlobalOptions{
		ConfigFile:            f.ConfigFile.Value(),
		ShowVersion:           f.ShowVersion.Value(),
		Quiet:                 f.Quiet.Value(),
		Debug:                 f.Debug.Value(),
		Insecure:              insecure,
		Timeout:               f.Timeout.Value(),
		CacheDir:              f.CacheDir.Value(),
		GenerateDefaultConfig: f.GenerateDefaultConfig.Value(),
	}, nil
}
