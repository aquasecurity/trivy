package flag

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/trivy/pkg/utils"
)

var (
	ConfigFileFlag = Flag{
		Name:       "config",
		ConfigName: "config",
		Shorthand:  "c",
		Value:      "trivy.yaml",
		Usage:      "config path",
	}
	ShowVersionFlag = Flag{
		Name:       "version",
		ConfigName: "version",
		Shorthand:  "v",
		Value:      false,
		Usage:      "show version",
	}
	QuietFlag = Flag{
		Name:       "quiet",
		ConfigName: "quiet",
		Shorthand:  "q",
		Value:      false,
		Usage:      "suppress progress bar and log output",
	}
	DebugFlag = Flag{
		Name:       "debug",
		ConfigName: "debug",
		Shorthand:  "d",
		Value:      false,
		Usage:      "debug mode",
	}
	InsecureFlag = Flag{
		Name:       "insecure",
		ConfigName: "insecure",
		Value:      false,
		Usage:      "allow insecure server connections when using TLS",
	}
	TimeoutFlag = Flag{
		Name:       "timeout",
		ConfigName: "timeout",
		Value:      time.Second * 300, // 5 mins
		Usage:      "timeout",
	}
	CacheDirFlag = Flag{
		Name:       "cache-dir",
		ConfigName: "cache.dir",
		Value:      utils.DefaultCacheDir(),
		Usage:      "cache directory",
	}
)

// GlobalFlags composes global flags
type GlobalFlags struct {
	ConfigFile  *Flag
	ShowVersion *Flag // spf13/cobra can't override the logic of version printing like VersionPrinter in urfave/cli. -v needs to be defined ourselves.
	Quiet       *Flag
	Debug       *Flag
	Insecure    *Flag
	Timeout     *Flag
	CacheDir    *Flag
}

// GlobalOptions defines flags and other configuration parameters for all the subcommands
type GlobalOptions struct {
	ConfigFile  string
	ShowVersion bool
	Quiet       bool
	Debug       bool
	Insecure    bool
	Timeout     time.Duration
	CacheDir    string
}

func NewGlobalFlags() *GlobalFlags {
	return &GlobalFlags{
		ConfigFile:  &ConfigFileFlag,
		ShowVersion: &ShowVersionFlag,
		Quiet:       &QuietFlag,
		Debug:       &DebugFlag,
		Insecure:    &InsecureFlag,
		Timeout:     &TimeoutFlag,
		CacheDir:    &CacheDirFlag,
	}
}

func (f *GlobalFlags) flags() []*Flag {
	return []*Flag{}
}

func (f *GlobalFlags) AddFlags(cmd *cobra.Command) {
	for _, flag := range f.flags() {
		addFlag(cmd, flag)
	}
}

func (f *GlobalFlags) Bind(cmd *cobra.Command) error {
	for _, flag := range f.flags() {
		if err := bind(cmd, flag); err != nil {
			return err
		}
	}
	return nil
}

func (f *GlobalFlags) ToOptions() GlobalOptions {
	return GlobalOptions{
		ConfigFile:  get[string](f.ConfigFile),
		ShowVersion: get[bool](f.ShowVersion),
		Quiet:       get[bool](f.Quiet),
		Debug:       get[bool](f.Debug),
		Insecure:    get[bool](f.Insecure),
		Timeout:     get[time.Duration](f.Timeout),
		CacheDir:    get[string](f.CacheDir),
	}
}
