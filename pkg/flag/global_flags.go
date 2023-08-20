package flag

import (
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

var (
	ConfigFileFlag = Flag{
		Name:       "config",
		ConfigName: "config",
		Shorthand:  "c",
		Default:    "trivy.yaml",
		Usage:      "config path",
		Persistent: true,
	}
	ShowVersionFlag = Flag{
		Name:       "version",
		ConfigName: "version",
		Shorthand:  "v",
		Default:    false,
		Usage:      "show version",
		Persistent: true,
	}
	QuietFlag = Flag{
		Name:       "quiet",
		ConfigName: "quiet",
		Shorthand:  "q",
		Default:    false,
		Usage:      "suppress progress bar and log output",
		Persistent: true,
	}
	DebugFlag = Flag{
		Name:       "debug",
		ConfigName: "debug",
		Shorthand:  "d",
		Default:    false,
		Usage:      "debug mode",
		Persistent: true,
	}
	InsecureFlag = Flag{
		Name:       "insecure",
		ConfigName: "insecure",
		Default:    false,
		Usage:      "allow insecure server connections",
		Persistent: true,
	}
	TimeoutFlag = Flag{
		Name:       "timeout",
		ConfigName: "timeout",
		Default:    time.Second * 300, // 5 mins
		Usage:      "timeout",
		Persistent: true,
	}
	CacheDirFlag = Flag{
		Name:       "cache-dir",
		ConfigName: "cache.dir",
		Default:    fsutils.CacheDir(),
		Usage:      "cache directory",
		Persistent: true,
	}
	GenerateDefaultConfigFlag = Flag{
		Name:       "generate-default-config",
		ConfigName: "generate-default-config",
		Default:    false,
		Usage:      "write the default config to trivy-default.yaml",
		Persistent: true,
	}
)

// GlobalFlagGroup composes global flags
type GlobalFlagGroup struct {
	ConfigFile            *Flag
	ShowVersion           *Flag // spf13/cobra can't override the logic of version printing like VersionPrinter in urfave/cli. -v needs to be defined ourselves.
	Quiet                 *Flag
	Debug                 *Flag
	Insecure              *Flag
	Timeout               *Flag
	CacheDir              *Flag
	GenerateDefaultConfig *Flag
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
		ConfigFile:            &ConfigFileFlag,
		ShowVersion:           &ShowVersionFlag,
		Quiet:                 &QuietFlag,
		Debug:                 &DebugFlag,
		Insecure:              &InsecureFlag,
		Timeout:               &TimeoutFlag,
		CacheDir:              &CacheDirFlag,
		GenerateDefaultConfig: &GenerateDefaultConfigFlag,
	}
}

func (f *GlobalFlagGroup) Name() string {
	return "Global"
}

func (f *GlobalFlagGroup) Flags() []*Flag {
	return []*Flag{
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
		addFlag(cmd, flag)
	}
}

func (f *GlobalFlagGroup) Bind(cmd *cobra.Command) error {
	for _, flag := range f.Flags() {
		if err := bind(cmd, flag); err != nil {
			return err
		}
	}
	return nil
}

func (f *GlobalFlagGroup) ToOptions() GlobalOptions {
	// Keep TRIVY_NON_SSL for backward compatibility
	insecure := GetBool(f.Insecure) || os.Getenv("TRIVY_NON_SSL") != ""

	return GlobalOptions{
		ConfigFile:            GetString(f.ConfigFile),
		ShowVersion:           GetBool(f.ShowVersion),
		Quiet:                 GetBool(f.Quiet),
		Debug:                 GetBool(f.Debug),
		Insecure:              insecure,
		Timeout:               GetDuration(f.Timeout),
		CacheDir:              GetString(f.CacheDir),
		GenerateDefaultConfig: GetBool(f.GenerateDefaultConfig),
	}
}
