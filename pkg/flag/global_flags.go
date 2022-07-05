package flag

import (
	"time"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/trivy/pkg/utils"
)

const (
	VersionFlag  = "version"
	QuietFlag    = "quiet"
	DebugFlag    = "debug"
	InsecureFlag = "insecure"
	TimeoutFlag  = "timeout"
	CacheDirFlag = "cache-dir"
)

// GlobalFlags composes global flags
type GlobalFlags struct {
	ShowVersion *bool // spf13/cobra doesn't have something like VersionPrinter in urfave/cli. -v needs to be defined ourselves.
	Quiet       *bool
	Debug       *bool
	Insecure    *bool
	Timeout     *time.Duration
	CacheDir    *string
}

// GlobalOptions defines flags and other configuration parameters for all the subcommands
type GlobalOptions struct {
	ShowVersion bool
	Quiet       bool
	Debug       bool
	Insecure    bool
	Timeout     time.Duration
	CacheDir    string
}

func NewGlobalDefaultFlags() *GlobalFlags {
	return &GlobalFlags{
		ShowVersion: lo.ToPtr(false),
		Quiet:       lo.ToPtr(false),
		Debug:       lo.ToPtr(false),
		Insecure:    lo.ToPtr(false),
		Timeout:     lo.ToPtr(time.Second * 300), // 5 mins
		CacheDir:    lo.ToPtr(utils.DefaultCacheDir()),
	}
}

func (f *GlobalFlags) AddFlags(cmd *cobra.Command) {
	if f.ShowVersion != nil {
		cmd.PersistentFlags().BoolP(VersionFlag, "v", *f.ShowVersion, "show version")
	}

	if f.Quiet != nil {
		cmd.PersistentFlags().BoolP(QuietFlag, "q", *f.Quiet, "suppress progress bar and log output")
	}

	if f.Debug != nil {
		cmd.PersistentFlags().BoolP(DebugFlag, "d", *f.Debug, "debug mode")
	}

	if f.Insecure != nil {
		cmd.PersistentFlags().Bool(InsecureFlag, *f.Insecure, "allow insecure server connections when using TLS")
	}

	if f.Timeout != nil {
		cmd.PersistentFlags().Duration(TimeoutFlag, *f.Timeout, "timeout")
	}

	if f.CacheDir != nil {
		cmd.PersistentFlags().String(CacheDirFlag, *f.CacheDir, "cache directory")
	}
}

func (f *GlobalFlags) ToOptions() GlobalOptions {
	return GlobalOptions{
		ShowVersion: viper.GetBool(VersionFlag),
		Quiet:       viper.GetBool(QuietFlag),
		Debug:       viper.GetBool(DebugFlag),
		Insecure:    viper.GetBool(InsecureFlag),
		Timeout:     viper.GetDuration(TimeoutFlag),
		CacheDir:    viper.GetString(CacheDirFlag),
	}
}
